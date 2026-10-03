//! Sandboxed extensions: immutable packages, a bounded protocol and isolated workers.
pub mod contract;
pub mod package;
pub mod registry;
pub mod manager;
pub mod runtime;

pub mod distribution;
#[cfg(feature = "extension-worker")]
pub mod worker;
