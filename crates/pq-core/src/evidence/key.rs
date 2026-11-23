//! Canonical collection identity.
//!
//! A [`CollectionKey`] is a SHA-256 over a deterministic, versioned canonical
//! representation of a collection request. Equivalent requests (e.g. the same
//! DNS name differing only in letter case, or the same URL differing only in
//! default port) produce the same key; any parameter that affects the response
//! produces a different key. Credentials and secrets are structurally excluded
//! from canonical representations: request types hold them outside the fields
//! handed to the canonical writer.
//!
//! A canonicalization version constant is prefixed into the digest input, so
//! changing canonicalization yields new identities rather than silently
//! aliasing old data.

use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fmt;

/// Version of the canonicalization scheme. Bump (and re-verify equivalence
/// tests) whenever canonical field encodings change meaning; old keys in the
/// store keep their identities.
pub const CANONICALIZATION_VERSION: u32 = 1;

/// SHA-256 content hash of a canonicalized collection request.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CollectionKey(pub(crate) [u8; 32]);

impl CollectionKey {
    /// Hash a request of the given collection kind.
    pub fn compute(kind: &'static str, req: &impl CollectionRequest) -> Self {
        let mut w = CanonicalWriter::new();
        w.str_field("kind", kind);
        req.write_canonical(&mut w);
        Self(w.finish())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Debug for CollectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CollectionKey({})", self.hex())
    }
}

impl fmt::Display for CollectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A collection request: the identity of a repeatable ask (source, target,
/// parameters). Implementations define which fields affect the response and
/// write exactly those to the canonical writer.
pub trait CollectionRequest: Send + Sync + 'static {
    /// Collection kind, e.g. `dns`, `http`, `tls`, `ct`, `rdap`, `ripestat`.
    const KIND: &'static str;

    /// Name of the refresh policy this request uses (before the collection
    /// outcome is known). Collectors may refine per-outcome (e.g. DNS negative
    /// answers) via [`crate::evidence::collector::Collector::policy_name`].
    fn policy_name(&self) -> Cow<'static, str> {
        Cow::Borrowed("default")
    }

    /// Write the canonical form of every parameter that affects the response.
    /// Field order must be fixed; use the tagged helpers on
    /// [`CanonicalWriter`]. NEVER write secrets here.
    fn write_canonical(&self, w: &mut CanonicalWriter);

    /// Advisory JSON projection of the key-affecting parameters, stored on the
    /// collection row for human inspection. Secrets excluded. The canonical
    /// writer is authoritative; this projection never feeds the key.
    fn stored_params(&self) -> serde_json::Value;

    /// The collection identity: SHA-256 over the versioned canonical form.
    fn key(&self) -> CollectionKey
    where
        Self: Sized,
    {
        CollectionKey::compute(Self::KIND, self)
    }
}

/// Deterministic, length-prefixed, tagged writer for canonical forms.
///
/// Every field is written as: tag name (length-prefixed UTF-8), then a
/// type-specific length-prefixed payload. Values are length-prefixed so field
/// boundaries are unambiguous.
pub struct CanonicalWriter {
    buf: Vec<u8>,
}

impl Default for CanonicalWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalWriter {
    pub fn new() -> Self {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"pq-intel/evidence/canonical\0");
        buf.extend_from_slice(&CANONICALIZATION_VERSION.to_le_bytes());
        Self { buf }
    }

    fn write_len(&mut self, len: usize) {
        self.buf.extend_from_slice(&(len as u64).to_le_bytes());
    }

    fn write_str(&mut self, s: &str) {
        self.write_len(s.len());
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn str_field(&mut self, tag: &str, value: &str) {
        self.write_str(tag);
        self.write_str(value);
    }

    pub fn opt_str_field(&mut self, tag: &str, value: Option<&str>) {
        self.write_str(tag);
        match value {
            Some(v) => {
                self.buf.push(1);
                self.write_str(v);
            }
            None => self.buf.push(0),
        }
    }

    pub fn u16_field(&mut self, tag: &str, value: u16) {
        self.write_str(tag);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u32_field(&mut self, tag: &str, value: u32) {
        self.write_str(tag);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u64_field(&mut self, tag: &str, value: u64) {
        self.write_str(tag);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn bool_field(&mut self, tag: &str, value: bool) {
        self.write_str(tag);
        self.buf.push(u8::from(value));
    }

    pub fn bytes_field(&mut self, tag: &str, value: &[u8]) {
        self.write_str(tag);
        self.write_len(value.len());
        self.buf.extend_from_slice(value);
    }

    pub fn opt_bytes_field(&mut self, tag: &str, value: Option<&[u8]>) {
        self.write_str(tag);
        match value {
            Some(v) => {
                self.buf.push(1);
                self.write_len(v.len());
                self.buf.extend_from_slice(v);
            }
            None => self.buf.push(0),
        }
    }

    /// A list of strings (order significant; sort before calling when order
    /// does not affect the response).
    pub fn str_list_field(&mut self, tag: &str, values: &[String]) {
        self.write_str(tag);
        self.write_len(values.len());
        for v in values {
            self.write_str(v);
        }
    }

    /// A list of string pairs, canonicalized by sorting a copy — use for
    /// header maps and other order-insensitive pairs.
    pub fn pair_list_field(&mut self, tag: &str, pairs: &[(String, String)]) {
        let mut sorted: Vec<(String, String)> = pairs.to_vec();
        sorted.sort();
        self.write_str(tag);
        self.write_len(sorted.len());
        for (k, v) in sorted {
            self.write_str(&k);
            self.write_str(&v);
        }
    }

    fn finish(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Domain-separate: hash the length first so different canonical forms
        // cannot collide by concatenation.
        hasher.update((self.buf.len() as u64).to_le_bytes());
        hasher.update(&self.buf);
        hasher.finalize().into()
    }
}

/// Canonicalize an HTTP(S) URL for identity purposes: lowercase scheme and
/// host, drop the default port, drop the fragment, sort query pairs. Path and
/// everything else are preserved as-is.
pub fn canonical_url(input: &str) -> Result<String, crate::evidence::error::Error> {
    let mut url = url::Url::parse(input)?;
    url.set_fragment(None);
    if let Some(host) = url.host_str() {
        let host = host.to_ascii_lowercase();
        let _ = url.set_host(Some(&host));
    }
    if let Some(port) = url.port() {
        let default_port = match url.scheme() {
            "http" => 80,
            "https" => 443,
            _ => u16::MAX,
        };
        if port == default_port {
            let _ = url.set_port(None);
        }
    }
    // Sort query pairs.
    if !url.query().unwrap_or_default().is_empty() {
        let mut pairs: Vec<String> = url
            .query_pairs()
            .map(|(k, v)| {
                let mut p = url::form_urlencoded::Serializer::new(String::new());
                p.append_pair(&k, &v);
                p.finish()
            })
            .collect();
        pairs.sort();
        let joined: String = pairs.join("&");
        url.set_query(Some(&joined));
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestReq {
        name: String,
        rtype: u16,
        /// Present but never read: the test asserts the secret never
        /// influences the key bytes.
        #[allow(dead_code)]
        secret: Option<String>,
    }

    impl CollectionRequest for TestReq {
        const KIND: &'static str = "test";
        fn write_canonical(&self, w: &mut CanonicalWriter) {
            // The secret is deliberately NOT written: canonicalization is
            // structurally incapable of including it.
            w.str_field("name", &self.name);
            w.u16_field("rtype", self.rtype);
        }
        fn stored_params(&self) -> serde_json::Value {
            serde_json::json!({ "name": self.name, "rtype": self.rtype })
        }
    }

    #[test]
    fn equivalent_requests_share_a_key() {
        let a = TestReq {
            name: "Example.COM".to_string(),
            rtype: 1,
            secret: None,
        };
        // Same after canonicalizing letter case (the request type is
        // responsible for canonicalizing its fields; here equivalence is
        // exercised via equal canonical content).
        let b = TestReq {
            name: "Example.COM".to_string(),
            rtype: 1,
            secret: Some("hunter2".into()),
        };
        assert_eq!(a.key(), b.key());
    }

    #[test]
    fn differing_parameters_differ_in_keys() {
        let a = TestReq {
            name: "example.com".to_string(),
            rtype: 1,
            secret: None,
        };
        let b = TestReq {
            name: "example.com".to_string(),
            rtype: 28,
            secret: None,
        };
        assert_ne!(a.key(), b.key());
        let c = TestReq {
            name: "example.org".to_string(),
            rtype: 1,
            secret: None,
        };
        assert_ne!(a.key(), c.key());
    }

    #[test]
    fn secrets_never_appear_in_the_key() {
        let secret = "SuperSecretToken12345";
        let a = TestReq {
            name: "example.com".into(),
            rtype: 1,
            secret: Some(secret.into()),
        };
        let canonical_hex = {
            let mut w = CanonicalWriter::new();
            w.str_field("kind", TestReq::KIND);
            a.write_canonical(&mut w);
            hex(&w.buf)
        };
        assert!(
            !canonical_hex
                .to_ascii_lowercase()
                .contains(&secret.to_ascii_lowercase())
        );
        // And a request without the secret has the identical key.
        let b = TestReq {
            name: "example.com".into(),
            rtype: 1,
            secret: None,
        };
        assert_eq!(a.key(), b.key());
    }

    #[test]
    fn keys_are_version_prefixed_and_stable() {
        let a = TestReq {
            name: "example.com".into(),
            rtype: 1,
            secret: None,
        };
        // Recompute via a fresh writer: stable across calls.
        assert_eq!(a.key(), a.key());
        // The version constant participates: bumping it changes keys (guard
        // against accidental removal of the version prefix).
        let with_v1 = {
            let mut w = CanonicalWriter::new();
            w.str_field("kind", TestReq::KIND);
            a.write_canonical(&mut w);
            w.finish()
        };
        let saved = CANONICALIZATION_VERSION;
        // Can't actually change the const; instead verify the writer buffers it.
        let w = CanonicalWriter::new();
        assert_eq!(&w.buf[28..32], &saved.to_le_bytes());
        let _ = with_v1;
    }

    #[test]
    fn canonical_url_normalizes_equivalent_forms() {
        assert_eq!(
            canonical_url("https://EXAMPLE.com:443/a?b=2&a=1#frag").unwrap(),
            canonical_url("https://example.com/a?a=1&b=2").unwrap()
        );
        assert_eq!(
            canonical_url("http://example.com:80/").unwrap(),
            canonical_url("http://example.com/").unwrap()
        );
        // Non-default ports are significant.
        assert_ne!(
            canonical_url("https://example.com:8443/").unwrap(),
            canonical_url("https://example.com/").unwrap()
        );
        // Paths are significant.
        assert_ne!(
            canonical_url("https://example.com/a").unwrap(),
            canonical_url("https://example.com/b").unwrap()
        );
    }

    #[test]
    fn pair_list_field_is_order_insensitive() {
        fn key_for(pairs: &[(String, String)]) -> [u8; 32] {
            let mut w = CanonicalWriter::new();
            w.pair_list_field("headers", pairs);
            w.finish()
        }
        let a = key_for(&[("a".into(), "1".into()), ("b".into(), "2".into())]);
        let b = key_for(&[("b".into(), "2".into()), ("a".into(), "1".into())]);
        assert_eq!(a, b);
    }

    #[test]
    fn hex_is_lowercase_and_even() {
        let k = TestReq {
            name: "x".into(),
            rtype: 1,
            secret: None,
        }
        .key();
        let h = k.hex();
        assert_eq!(h.len(), 64);
        assert_eq!(h, h.to_ascii_lowercase());
    }
}
