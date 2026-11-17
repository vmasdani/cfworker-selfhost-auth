//! Standalone mode in Rust: an app's Worker code on a native server with a local SQLite file instead
//! of D1, serving its built web app. Drop-in for `packages/standalone` (Bun): same environment
//! variables, data directory layout, `d1_migrations` table, secrets files and HTTP behaviour.

pub mod dotenv;
pub mod migrate;
pub mod server;
pub mod sqlite;
pub mod static_site;

pub use server::{Options, run};
