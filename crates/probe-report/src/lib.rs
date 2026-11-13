//! Text and HTML reports from a [`Summary`].
//!
//! The HTML page is one self-contained file: inline CSS, no scripts, no
//! external resources, so it can be mailed or archived as is. Peer
//! addresses never appear: the summary does not carry them.

#![forbid(unsafe_code)]

use probe_analyzer::{phase_str, Bucket, JoinOutcome, Summary};
use std::fmt::Write as _;

/// What the report is about, shown in its header.
#[derive(Debug, Clone, Default)]
pub struct Meta {
    pub title: String,
    /// e.g. "last 24h".
    pub window: String,
    pub generated_at: String,
}

fn pct(b: &Bucket) -> String {
    b.success_rate()
        .map(|r| format!("{:.1}%", r * 100.0))
        .unwrap_or_else(|| "-".into())
}

fn ms(v: Option<u64>) -> String {
    v.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
}

fn errors(b: &Bucket) -> String {
    b.errors
        .iter()
        .map(|(c, n)| format!("{c}×{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn stopped_at(b: &Bucket) -> String {
    b.failed_at
        .iter()
        .map(|(p, n)| format!("{}×{n}", phase_str(*p)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_label(o: JoinOutcome) -> &'static str {
    match o {
        JoinOutcome::ClientOk => "client ok",
        JoinOutcome::FailedServerSaw => "client failed, server saw the request",
        JoinOutcome::FailedServerSilent => "client failed, server saw nothing",
    }
}

/// Plain-text report for the terminal.
pub fn render_text(s: &Summary, meta: &Meta) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "{} ({})", meta.title, meta.window);
    let _ = writeln!(
        o,
        "client events: {}, server events: {}, unreadable lines: {}",
        s.client_events, s.server_events, s.bad_lines
    );
    if let (Some(a), Some(b)) = (&s.first, &s.last) {
        let _ = writeln!(o, "from {a} to {b}");
    }
    if s.buckets.is_empty() {
        let _ = writeln!(o, "\nno client events in this window");
        return o;
    }
    let _ = writeln!(
        o,
        "\n{:<44} {:>6} {:>7} {:>7} {:>7} {:>7}  failures",
        "test", "total", "ok", "p50 ms", "p90 ms", "max ms"
    );
    for (name, (_, b)) in &s.buckets {
        let _ = write!(
            o,
            "{:<44} {:>6} {:>7} {:>7} {:>7} {:>7}",
            name,
            b.total,
            pct(b),
            ms(b.ok_ms.p50),
            ms(b.ok_ms.p90),
            ms(b.ok_ms.max)
        );
        if !b.errors.is_empty() {
            let _ = write!(o, "  {} (stopped at {})", errors(b), stopped_at(b));
        }
        let _ = writeln!(o);
    }
    if !s.joined.is_empty() {
        let _ = writeln!(o, "\nclient/server join (requests carrying a test id):");
        for (k, n) in &s.joined {
            let _ = writeln!(o, "  {:<42} {n}", join_label(*k));
        }
    }
    if s.pairs.total > 0 {
        let p = s.pairs;
        let _ = writeln!(
            o,
            "\npaired cascade probes: {} (both ok {}, upload failed {}, download failed {}, both failed {}, incomplete {})",
            p.total, p.both_ok, p.only_up_failed, p.only_down_failed, p.both_failed, p.incomplete
        );
    }
    o
}

/// Escapes text for HTML element content and attribute values.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

const CSS: &str =
    "body{font:14px/1.45 system-ui,sans-serif;margin:24px;color:#1b1b1b;background:#fff}\
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 8px}\
.meta{color:#555}table{border-collapse:collapse;width:100%;max-width:1100px}\
th,td{border-bottom:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}\
td.n{text-align:right;font-variant-numeric:tabular-nums}\
.bad{color:#a40000}.good{color:#1a6b1a}\
@media (prefers-color-scheme:dark){body{background:#151515;color:#e6e6e6}\
th,td{border-color:#333}.meta{color:#aaa}.bad{color:#ff8a8a}.good{color:#8fd88f}}";

/// Self-contained HTML report.
pub fn render_html(s: &Summary, meta: &Meta) -> String {
    let mut o = String::new();
    let _ = write!(
        o,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{}</title><style>{CSS}</style></head><body>",
        esc(&meta.title)
    );
    let _ = write!(
        o,
        "<h1>{}</h1><p class=\"meta\">{} · generated {} · client events {} · server events {} · unreadable lines {}",
        esc(&meta.title),
        esc(&meta.window),
        esc(&meta.generated_at),
        s.client_events,
        s.server_events,
        s.bad_lines
    );
    if let (Some(a), Some(b)) = (&s.first, &s.last) {
        let _ = write!(o, " · {} – {}", esc(a), esc(b));
    }
    o.push_str("</p>");

    o.push_str("<h2>Tests</h2>");
    if s.buckets.is_empty() {
        o.push_str("<p>No client events in this window.</p>");
    } else {
        o.push_str(
            "<table><thead><tr><th>Target</th><th>Test</th><th>Transport</th><th>Dir</th>\
             <th>Total</th><th>OK</th><th>p50 ms</th><th>p90 ms</th><th>max ms</th>\
             <th>Errors</th><th>Stopped at</th><th>Networks</th></tr></thead><tbody>",
        );
        for (k, b) in s.buckets.values() {
            let cls = match b.success_rate() {
                Some(r) if r >= 0.99 => "good",
                Some(_) => "bad",
                None => "",
            };
            let _ = write!(
                o,
                "<tr><td>{}{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"n\">{}</td>\
                 <td class=\"n {cls}\">{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td>\
                 <td class=\"n\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                if k.control { "control " } else { "" },
                esc(&k.target_id),
                k.test_type.as_str(),
                probe_analyzer::transport_str(k.transport),
                k.direction.map(|d| d.as_str()).unwrap_or(""),
                b.total,
                pct(b),
                ms(b.ok_ms.p50),
                ms(b.ok_ms.p90),
                ms(b.ok_ms.max),
                esc(&errors(b)),
                esc(&stopped_at(b)),
                esc(&b.networks.join(", "))
            );
        }
        o.push_str("</tbody></table>");
    }

    if !s.joined.is_empty() {
        o.push_str(
            "<h2>Client and server</h2><p class=\"meta\">Requests that carry the client's test id, matched against the server journal.</p><table><tbody>",
        );
        for (k, n) in &s.joined {
            let _ = write!(
                o,
                "<tr><td>{}</td><td class=\"n\">{n}</td></tr>",
                join_label(*k)
            );
        }
        o.push_str("</tbody></table>");
    }

    if s.pairs.total > 0 {
        let p = s.pairs;
        let _ = write!(
            o,
            "<h2>Paired cascade probes</h2><table><tbody>\
             <tr><td>Total</td><td class=\"n\">{}</td></tr>\
             <tr><td>Both directions ok</td><td class=\"n\">{}</td></tr>\
             <tr><td>Upload failed</td><td class=\"n\">{}</td></tr>\
             <tr><td>Download failed</td><td class=\"n\">{}</td></tr>\
             <tr><td>Both failed</td><td class=\"n\">{}</td></tr>\
             <tr><td>Incomplete</td><td class=\"n\">{}</td></tr></tbody></table>",
            p.total, p.both_ok, p.only_up_failed, p.only_down_failed, p.both_failed, p.incomplete
        );
    }
    o.push_str(
        "<p class=\"meta\">Codes name what the probe observed, not why: a timeout is a timeout, not proof of filtering.</p></body></html>\n",
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe_analyzer::{summarize, Journal};
    use probe_common::{ErrorCode, ProbeEvent, TestType, Transport};

    fn summary() -> Summary {
        let ok = ProbeEvent::new(
            "1",
            "c",
            "net<a>",
            "gw&1",
            TestType::TcpConnect,
            Transport::Tcp,
        )
        .succeed();
        let bad = ProbeEvent::new(
            "2",
            "c",
            "net<a>",
            "gw&1",
            TestType::TcpConnect,
            Transport::Tcp,
        )
        .fail(ErrorCode::TcpTimeout, "x");
        summarize(
            &Journal {
                events: vec![ok, bad],
                ..Journal::default()
            },
            false,
        )
    }

    #[test]
    fn text_lists_buckets() {
        let t = render_text(&summary(), &Meta::default());
        assert!(t.contains("gw&1 tcp_connect tcp"), "{t}");
        assert!(t.contains("50.0%"), "{t}");
        assert!(t.contains("tcp_timeout×1"), "{t}");
    }

    #[test]
    fn html_is_escaped_and_self_contained() {
        let h = render_html(
            &summary(),
            &Meta {
                title: "<script>".into(),
                ..Meta::default()
            },
        );
        assert!(!h.contains("<script>"), "{h}");
        assert!(h.contains("&lt;script&gt;"));
        assert!(h.contains("gw&amp;1"));
        assert!(h.contains("net&lt;a&gt;"));
        assert!(!h.contains("http://") && !h.contains("https://"));
    }
}
