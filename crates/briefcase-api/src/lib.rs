//! Briefcase daemon API types and a small client.
//!
//! This crate exists so the daemon, MCP gateway, and CLI share a stable contract.

pub mod client;
pub mod types;

pub use client::{BriefcaseClient, BriefcaseClientError, DaemonEndpoint};
pub use types::*;
