//! Packet routing between the TUN device and client sessions
//! (`docs/design/network.md`).

use crate::config::Client;
use astp_session::{
    code, run, server_handshake, EndReason, Link, Packet, Role, SessionParams, Stats,
};
use astp_transport::Accepted;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

/// Packets queued per session towards the client.
const SESSION_QUEUE: usize = 512;

#[derive(Default)]
struct Table {
    by_addr: HashMap<IpAddr, (u64, mpsc::Sender<Packet>)>,
    by_client: HashMap<String, (u64, oneshot::Sender<u16>)>,
}

/// The server's routing state, shared by every session task.
pub struct Core {
    clients: HashMap<Vec<u8>, Client>,
    base: SessionParams,
    prefix4: u8,
    prefix6: Option<u8>,
    to_tun: mpsc::Sender<Packet>,
    table: Mutex<Table>,
    seq: AtomicU64,
    handshake_timeout: Duration,
}

impl Core {
    /// `base` carries everything but the per-client addresses and id.
    pub fn new(
        clients: Vec<Client>,
        base: SessionParams,
        prefix4: u8,
        prefix6: Option<u8>,
        to_tun: mpsc::Sender<Packet>,
        handshake_timeout: Duration,
    ) -> Core {
        Core {
            clients: clients
                .into_iter()
                .map(|c| (c.name.as_bytes().to_vec(), c))
                .collect(),
            base,
            prefix4,
            prefix6,
            to_tun,
            table: Mutex::new(Table::default()),
            seq: AtomicU64::new(1),
            handshake_timeout,
        }
    }

    /// Hands a packet from the TUN device to the session that owns its
    /// destination; without one the packet is dropped.
    pub fn dispatch(&self, pkt: Packet) {
        let Some(dst) = astp_tun::packet::destination(&pkt) else {
            return;
        };
        let tx = self
            .table
            .lock()
            .expect("routing table lock")
            .by_addr
            .get(&dst)
            .map(|(_, tx)| tx.clone());
        if let Some(tx) = tx {
            // A full queue drops, like a congested interface.
            let _ = tx.try_send(pkt);
        }
    }

    /// Number of clients with a running session.
    pub fn sessions(&self) -> usize {
        self.table
            .lock()
            .expect("routing table lock")
            .by_client
            .len()
    }

    /// Runs one accepted session to its end.
    pub async fn handle(self: Arc<Self>, acc: Accepted, mut shutdown: watch::Receiver<bool>) {
        let Some(client) = self.clients.get(acc.client.as_bytes()).cloned() else {
            tracing::warn!("authenticated client is not configured");
            return;
        };
        let name = client.name.clone();
        let params = SessionParams {
            addr4: Some((client.address4, self.prefix4)),
            addr6: client.address6.zip(self.prefix6),
            session_id: rand::random(),
            ..self.base.clone()
        };
        let mut reader = astp_frame::FrameReader::new(acc.io.reader);
        let mut writer = acc.io.writer;
        if let Err(e) =
            server_handshake(&mut reader, &mut writer, &params, self.handshake_timeout).await
        {
            tracing::info!(client = %name, peer = %acc.peer, "handshake failed: {e}");
            return;
        }

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let (pkt_tx, pkt_rx) = mpsc::channel(SESSION_QUEUE);
        let (stop_tx, stop_rx) = oneshot::channel();
        let mine: Vec<IpAddr> = std::iter::once(IpAddr::V4(client.address4))
            .chain(client.address6.map(IpAddr::V6))
            .collect();
        {
            let mut t = self.table.lock().expect("routing table lock");
            if let Some((_, old)) = t.by_client.insert(name.clone(), (seq, stop_tx)) {
                // One session per client: the newer one wins.
                let _ = old.send(code::REPLACED);
            }
            for a in &mine {
                t.by_addr.insert(*a, (seq, pkt_tx.clone()));
            }
        }
        tracing::info!(client = %name, peer = %acc.peer, transport = acc.transport, "session up");

        // Packets from the client reach the TUN only with its own source.
        let (local_tx, mut local_rx) = mpsc::channel::<Packet>(SESSION_QUEUE);
        let to_tun = self.to_tun.clone();
        let allowed = mine.clone();
        let spoofed = Arc::new(AtomicU64::new(0));
        let spoofed_w = spoofed.clone();
        let forward = tokio::spawn(async move {
            while let Some(p) = local_rx.recv().await {
                match astp_tun::packet::source(&p) {
                    Some(src) if allowed.contains(&src) => {
                        let _ = to_tun.try_send(p);
                    }
                    _ => {
                        spoofed_w.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        let stats = Arc::new(Stats::default());
        let stop = async move {
            tokio::select! {
                c = stop_rx => c.unwrap_or(code::REPLACED),
                _ = shutdown.changed() => code::SERVER_SHUTDOWN,
            }
        };
        let end = run(
            Role::Server,
            reader,
            writer,
            &params,
            Link {
                to_local: local_tx,
                from_local: pkt_rx,
                events: None,
            },
            stats.clone(),
            stop,
        )
        .await;
        forward.abort();
        {
            let mut t = self.table.lock().expect("routing table lock");
            if t.by_client.get(&name).is_some_and(|(s, _)| *s == seq) {
                t.by_client.remove(&name);
            }
            for a in &mine {
                if t.by_addr.get(a).is_some_and(|(s, _)| *s == seq) {
                    t.by_addr.remove(a);
                }
            }
        }
        let ld = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let how = match &end {
            EndReason::Failed(e) => format!("failed: {e}"),
            other => format!("{other:?}"),
        };
        tracing::info!(
            client = %name,
            end = %how,
            rx_packets = ld(&stats.received_packets),
            tx_packets = ld(&stats.sent_packets),
            dropped_no_credit = ld(&stats.dropped_no_credit),
            spoofed = spoofed.load(Ordering::Relaxed),
            "session down"
        );
    }
}
