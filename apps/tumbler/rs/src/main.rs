//! Standalone mode: Tumbler on a native server with SQLite (see crates/standalone).
//!   cargo build --release -p tumbler-rs --bin tumbler-server
//!   STATIC_DIR=apps/tumbler/dist ./target/release/tumbler-server

#[cfg(not(target_arch = "wasm32"))]
fn main() {
	cfsa_standalone::run(
		tumbler_rs::Tumbler,
		cfsa_standalone::Options { name: "tumbler", default_port: 8701, installer_app: "tumbler", migrations: tumbler_rs::MIGRATIONS },
	);
}

#[cfg(target_arch = "wasm32")]
fn main() {}
