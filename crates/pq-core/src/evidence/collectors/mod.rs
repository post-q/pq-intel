//! The v1 collectors: every collection path that exists across the pq-intel
//! tools, unified over the evidence store.
//!
//! Production transports (ureq HTTP, std UDP/TCP DNS via hickory-proto
//! wire-format, rustls TLS) live beside the traits they implement, so tests
//! run the same collectors against canned transports.

pub mod ct;
pub mod ctdb;
pub mod dns;
pub mod dns_transport;
pub mod http_collector;
#[cfg(feature = "openssl-tls")]
pub mod openssl_tls;
pub mod ports;
pub mod rdap;
pub mod ripestat;
pub mod tls;
pub mod tls_connector;
