//! Standalone mode: Coffer on a native server with SQLite (see crates/standalone).
//!   cargo build --release -p coffer-rs --bin coffer-server
//!   STATIC_DIR=apps/coffer/dist ./target/release/coffer-server

#[cfg(not(target_arch = "wasm32"))]
fn main() {
	cfsa_standalone::run(
		coffer_rs::Coffer,
		cfsa_standalone::Options { name: "coffer", default_port: 8702, installer_app: "coffer", migrations: coffer_rs::MIGRATIONS },
	);
}

#[cfg(target_arch = "wasm32")]
fn main() {}
