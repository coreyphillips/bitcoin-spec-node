//! Bitcoin consensus rules, written from the specification package (`spec-package/`, version
//! `v32.1-1`). One module per chapter; see each module's header for its chapter.

pub mod block_rules; // chapter 10
pub mod chain; // chapter 11 (and 10.8)
pub mod coins; // UTXO cache and chapter 15
pub mod crypto; // chapter 02, sections 2.8 to 2.11
pub mod hashes; // chapter 02, sections 2.1 to 2.4
pub mod interpreter; // chapter 05
pub mod p2p; // chapter 14
pub mod params; // chapter 12
pub mod pow; // chapter 09
pub mod script; // chapter 04
pub mod serialize; // chapter 03, section 3.1
pub mod sighash; // chapter 06
pub mod signet; // chapter 13
pub mod tx; // chapter 03
pub mod tx_rules; // chapter 08
pub mod uint; // chapter 02, section 2.5
pub mod util; // chapter 01
pub mod verify; // chapter 07

/// Specification version implemented.
pub const SPEC_VERSION: &str = "v32.1-1";
