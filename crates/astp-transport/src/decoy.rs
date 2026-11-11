//! The site every unauthenticated visitor sees (`docs/design/session.md`).
//!
//! A wrong path, a wrong method, a missing or invalid credential and a
//! plain browser visit all get the same answers, so probing the session
//! path tells nothing.

use bytes::Bytes;
use http::{Method, Response, StatusCode};

/// Pages of the decoy site.
#[derive(Debug, Clone)]
pub struct Decoy {
    /// Served for `GET /` and `HEAD /`.
    pub index_html: Bytes,
    /// Served with 404 for everything else.
    pub not_found_html: Bytes,
}

impl Default for Decoy {
    fn default() -> Self {
        Decoy {
            index_html: Bytes::from_static(
                b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Welcome</title></head>\
<body><h1>Welcome</h1><p>This site is under construction.</p></body></html>\n",
            ),
            not_found_html: Bytes::from_static(
                b"<!doctype html><html><head><meta charset=\"utf-8\"><title>404 Not Found</title></head>\
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n",
            ),
        }
    }
}

impl Decoy {
    /// The answer for a request that is not an authenticated session.
    pub fn respond(&self, method: &Method, path: &str) -> Response<Bytes> {
        let (status, body) = if path == "/" && (method == Method::GET || method == Method::HEAD) {
            (StatusCode::OK, self.index_html.clone())
        } else {
            (StatusCode::NOT_FOUND, self.not_found_html.clone())
        };
        let body = if method == Method::HEAD {
            Bytes::new()
        } else {
            body
        };
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(body)
            .expect("static response is valid")
    }
}
