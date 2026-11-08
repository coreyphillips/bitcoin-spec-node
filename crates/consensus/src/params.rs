//! Chapter 12: network parameters.

use crate::hashes::sha256d;
use crate::interpreter::{ScriptFlags, VERIFY_P2SH, VERIFY_WITNESS};
use crate::script::{push_data, push_int, OP_CHECKSIG};
use crate::serialize::write_var_bytes;
use crate::tx::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};
use crate::uint::U256;
use crate::util::{hash_from_display, hex_decode, Hash256, COIN, ZERO_HASH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Main,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

impl Network {
    /// Parses the names used by PROTOCOL.md and the command line.
    pub fn from_name(name: &str) -> Option<Network> {
        match name {
            "main" | "mainnet" => Some(Network::Main),
            "testnet3" | "testnet" | "test" => Some(Network::Testnet3),
            "testnet4" => Some(Network::Testnet4),
            "signet" => Some(Network::Signet),
            "regtest" => Some(Network::Regtest),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Network::Main => "main",
            Network::Testnet3 => "testnet3",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }
}

/// Consensus parameters. Core: `Consensus::Params`.
#[derive(Clone, Debug)]
pub struct ConsensusParams {
    pub network: Network,
    pub genesis_hash: Hash256,
    pub subsidy_halving_interval: i32,
    pub bip34_height: i32,
    pub bip34_hash: Hash256,
    pub bip65_height: i32,
    pub bip66_height: i32,
    pub csv_height: i32,
    pub segwit_height: i32,
    pub pow_limit: U256,
    pub pow_target_timespan: i64,
    pub pow_target_spacing: i64,
    pub pow_allow_min_difficulty_blocks: bool,
    pub pow_no_retargeting: bool,
    pub enforce_bip94: bool,
    /// Blocks whose script flags differ from the default (chapter 10).
    pub script_flag_exceptions: Vec<(Hash256, ScriptFlags)>,
    /// Signet only: the block signing challenge (chapter 13).
    pub signet_challenge: Option<Vec<u8>>,
}

impl ConsensusParams {
    /// Core: `Consensus::Params::DifficultyAdjustmentInterval`.
    pub fn difficulty_adjustment_interval(&self) -> i64 {
        self.pow_target_timespan / self.pow_target_spacing
    }
}

/// Everything a node needs to know about a network.
#[derive(Clone, Debug)]
pub struct NetworkParams {
    pub consensus: ConsensusParams,
    pub genesis: Block,
    /// The four bytes that start every peer-to-peer message (chapter 14).
    pub magic: [u8; 4],
    pub default_port: u16,
}

/// Core: `CreateGenesisBlock`.
pub fn create_genesis_block(message: &[u8], output_script: Vec<u8>, time: u32, nonce: u32, bits: u32, version: i32, reward: i64) -> Block {
    let mut script_sig = push_int(486604799);
    script_sig.extend_from_slice(&push_data(&[4]));
    script_sig.extend_from_slice(&push_data(message));
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: OutPoint::null(), script_sig, sequence: 0xffff_ffff, witness: Vec::new() }],
        outputs: vec![TxOut { value: reward, script_pubkey: output_script }],
        lock_time: 0,
    };
    let merkle_root = coinbase.txid();
    Block { header: BlockHeader { version, prev_block: ZERO_HASH, merkle_root, time, bits, nonce }, transactions: vec![coinbase] }
}

const SATOSHI_MESSAGE: &[u8] = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
const SATOSHI_PUBKEY: &str = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f";
const TESTNET4_MESSAGE: &[u8] = b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";

fn p2pk_script(pubkey: &[u8]) -> Vec<u8> {
    let mut script = push_data(pubkey);
    script.push(OP_CHECKSIG);
    script
}

/// The default signet challenge. Core: `SigNetParams`.
pub const DEFAULT_SIGNET_CHALLENGE: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";

/// Test overrides. Core: `CChainParams::DeploymentOptions`, `RegTestOptions`, `SigNetOptions`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkOptions {
    /// `(name, height)` with name one of bip34, dersig, cltv, csv, segwit.
    pub activation_heights: Vec<(String, i32)>,
    /// Regtest only.
    pub enforce_bip94: bool,
    /// Signet only.
    pub signet_challenge: Option<Vec<u8>>,
}

fn hash_from_hex(display: &str) -> Hash256 {
    hash_from_display(display).expect("valid constant")
}

fn target_from_hex(text: &str) -> U256 {
    U256::from_be_bytes(&hex_decode(text).expect("valid constant"))
}

/// Builds the parameters of a network. Returns an error for an invalid override name or a
/// mainnet override (the reference panics).
pub fn try_network_params(network: Network, options: &NetworkOptions) -> Result<NetworkParams, String> {
    let satoshi_script = p2pk_script(&hex_decode(SATOSHI_PUBKEY).unwrap());
    let main_limit = target_from_hex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let two_weeks = 14 * 24 * 60 * 60;
    let mut consensus = ConsensusParams {
        network,
        genesis_hash: ZERO_HASH,
        subsidy_halving_interval: 210_000,
        bip34_height: 1,
        bip34_hash: ZERO_HASH,
        bip65_height: 1,
        bip66_height: 1,
        csv_height: 1,
        segwit_height: 1,
        pow_limit: main_limit,
        pow_target_timespan: two_weeks,
        pow_target_spacing: 10 * 60,
        pow_allow_min_difficulty_blocks: false,
        pow_no_retargeting: false,
        enforce_bip94: false,
        script_flag_exceptions: Vec::new(),
        signet_challenge: None,
    };
    let (genesis, magic, default_port) = match network {
        Network::Main => {
            consensus.bip34_height = 227_931;
            consensus.bip34_hash = hash_from_hex("000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
            consensus.bip65_height = 388_381;
            consensus.bip66_height = 363_725;
            consensus.csv_height = 419_328;
            consensus.segwit_height = 481_824;
            consensus.script_flag_exceptions = vec![
                // BIP16 exception: block 170060.
                (hash_from_hex("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"), 0),
                // Taproot exception: block 692261.
                (hash_from_hex("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"), VERIFY_P2SH | VERIFY_WITNESS),
            ];
            (create_genesis_block(SATOSHI_MESSAGE, satoshi_script, 1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN), [0xf9, 0xbe, 0xb4, 0xd9], 8333)
        }
        Network::Testnet3 => {
            consensus.bip34_height = 21_111;
            consensus.bip34_hash = hash_from_hex("0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
            consensus.bip65_height = 581_885;
            consensus.bip66_height = 330_776;
            consensus.csv_height = 770_112;
            consensus.segwit_height = 834_624;
            consensus.pow_allow_min_difficulty_blocks = true;
            consensus.script_flag_exceptions = vec![(hash_from_hex("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"), 0)];
            (create_genesis_block(SATOSHI_MESSAGE, satoshi_script, 1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN), [0x0b, 0x11, 0x09, 0x07], 18333)
        }
        Network::Testnet4 => {
            consensus.pow_allow_min_difficulty_blocks = true;
            consensus.enforce_bip94 = true;
            let script = p2pk_script(&[0u8; 33]);
            (create_genesis_block(TESTNET4_MESSAGE, script, 1714777860, 393743547, 0x1d00ffff, 1, 50 * COIN), [0x1c, 0x16, 0x3f, 0x28], 48333)
        }
        Network::Signet => {
            consensus.pow_limit = target_from_hex("00000377ae000000000000000000000000000000000000000000000000000000");
            let challenge = options.signet_challenge.clone().unwrap_or_else(|| hex_decode(DEFAULT_SIGNET_CHALLENGE).unwrap());
            let mut serialized = Vec::new();
            write_var_bytes(&mut serialized, &challenge);
            let digest = sha256d(&serialized);
            consensus.signet_challenge = Some(challenge);
            (create_genesis_block(SATOSHI_MESSAGE, satoshi_script, 1598918400, 52613770, 0x1e0377ae, 1, 50 * COIN), [digest[0], digest[1], digest[2], digest[3]], 38333)
        }
        Network::Regtest => {
            consensus.subsidy_halving_interval = 150;
            consensus.segwit_height = 0;
            consensus.pow_limit = target_from_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            consensus.pow_target_timespan = 24 * 60 * 60;
            consensus.pow_allow_min_difficulty_blocks = true;
            consensus.pow_no_retargeting = true;
            consensus.enforce_bip94 = options.enforce_bip94;
            (create_genesis_block(SATOSHI_MESSAGE, satoshi_script, 1296688602, 2, 0x207fffff, 1, 50 * COIN), [0xfa, 0xbf, 0xb5, 0xda], 18444)
        }
    };
    if !options.activation_heights.is_empty() && network == Network::Main {
        return Err("deployment overrides are not allowed on mainnet".to_string());
    }
    for (name, height) in &options.activation_heights {
        match name.as_str() {
            "bip34" => consensus.bip34_height = *height,
            "dersig" => consensus.bip66_height = *height,
            "cltv" => consensus.bip65_height = *height,
            "csv" => consensus.csv_height = *height,
            "segwit" => consensus.segwit_height = *height,
            other => return Err(format!("unknown deployment {other}")),
        }
    }
    consensus.genesis_hash = genesis.hash();
    Ok(NetworkParams { consensus, genesis, magic, default_port })
}

/// Builds the parameters of a network. Panics on an invalid override name or a mainnet override.
pub fn network_params(network: Network, options: &NetworkOptions) -> NetworkParams {
    try_network_params(network, options).expect("valid network options")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hash_to_display, hex_encode};

    #[test]
    fn genesis_hashes() {
        let expect = [
            (Network::Main, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
            (Network::Testnet3, "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
            (Network::Testnet4, "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
            (Network::Signet, "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
            (Network::Regtest, "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
        ];
        for (network, hash) in expect {
            let params = network_params(network, &NetworkOptions::default());
            assert_eq!(hash_to_display(&params.consensus.genesis_hash), hash, "{network:?}");
        }
        let main = network_params(Network::Main, &NetworkOptions::default());
        assert_eq!(hash_to_display(&main.genesis.header.merkle_root), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        let testnet4 = network_params(Network::Testnet4, &NetworkOptions::default());
        assert_eq!(hash_to_display(&testnet4.genesis.header.merkle_root), "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e");
        let signet = network_params(Network::Signet, &NetworkOptions::default());
        assert_eq!(hex_encode(&signet.magic), "0a03cf40");
    }
}
