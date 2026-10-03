//! Native Vyx AI host services. Everything here stays on the host side of the extension boundary:
//! guests never receive provider credentials, conversation history, terminal context, or actions.

pub(crate) mod actions;
pub mod codex;
mod codex_runtime;
pub(crate) mod model;
pub mod providers;

pub use model::*;
