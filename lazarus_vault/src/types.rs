use soroban_sdk::{contracterror, contractevent, contracttype, Address, BytesN};

pub const DAY_IN_LEDGERS: u32 = 17_280;
pub const BUMP_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS; // 30 days (~518,400 ledgers)
pub const BUMP_TO: u32 = 120 * DAY_IN_LEDGERS; // 120 days (~2,073,600 ledgers)
pub const MAX_TTL_LEDGERS: u32 = 180 * DAY_IN_LEDGERS; // 180 days (~3,110,400 ledgers Soroban ceiling)
pub const MIN_THRESHOLD_LEDGERS: u32 = 100;
pub const MAX_BATCH_SIZE: u32 = 10;
pub const PROTOCOL_FEE_BPS: i128 = 500; // 5.00% (500 basis points)
pub const BPS_DENOMINATOR: i128 = 10_000;

#[contractevent]
pub struct ContractRegistered {
    #[topic]
    pub target: Address,
    #[topic]
    pub client: Address,
    pub initial_deposit: i128,
    pub fixed_bounty: i128,
}

#[contractevent]
pub struct FundsDeposited {
    #[topic]
    pub target: Address,
    #[topic]
    pub client: Address,
    pub amount: i128,
    pub new_balance: i128,
}

#[contractevent]
pub struct BumpRecorded {
    #[topic]
    pub keeper: Address,
    #[topic]
    pub target_contract: Address,
    pub nonce: u64,
    pub bounty_amount: i128,
    pub protocol_fee: i128,
}

#[contractevent]
pub struct EmergencyWithdrawn {
    #[topic]
    pub target: Address,
    #[topic]
    pub client: Address,
    pub refund: i128,
}

#[contractevent]
pub struct ProtocolFeesWithdrawn {
    #[topic]
    pub admin: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contractevent]
pub struct OraclePubKeyRotated {
    #[topic]
    pub admin: Address,
    pub new_oracle_pubkey: BytesN<32>,
}

#[contractevent]
pub struct MaxHourlyOutflowUpdated {
    #[topic]
    pub admin: Address,
    pub new_max_outflow: i128,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VaultError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    ContractInactive = 3,
    InsufficientEscrow = 4,
    InvalidNonce = 5,
    BountyMismatch = 6,
    BountyOutOfBounds = 7,
    ArithmeticError = 8,
    // Note: Error code 9 was previously assigned to InvalidSignature.
    // In Soroban, env.crypto().ed25519_verify() panics/traps directly at the host VM level
    // upon verification failure rather than returning a Result. InvalidSignature was removed
    // from the error enum to avoid dead, unreachable error variants in the contract interface.
    BatchSizeExceeded = 10,
    VectorMismatch = 11,
    Unauthorized = 12,
    HourlyOutflowExceeded = 13,
    InvalidTarget = 14,
    AlreadyRegistered = 15,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BountyPolicy {
    Fixed(i128),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultConfig {
    pub client: Address,                   // Depositor / Protocol Admin
    pub balance: i128,                     // Escrow reserve (in stroops, i128)
    pub policy: BountyPolicy,              // Strict bounty rate enforcement
    pub min_ledger_threshold: u32,         // Trigger window (e.g. < 20,000 ledgers)
    pub bump_target: u32,                  // Target TTL addition (e.g. 500,000 ledgers)
    pub max_contract_hourly_outflow: i128, // Per-contract hourly circuit breaker limit
    pub is_active: bool,                   // Active monitoring flag
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BumpVoucher {
    pub keeper: Address,          // Recipient node operator
    pub target_contract: Address, // Enrolled contract extended
    pub ledger_bumped: u32,       // Target ledger sequence achieved
    pub bounty_amount: i128,      // Deterministic payout amount (i128)
    pub nonce: u64, // Per-keeper voucher nonce (supports out-of-order batch settlement)
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    OraclePubKey,                        // 32-byte Ed25519 / FROST group public key
    Token,                               // SAC Token Address (e.g. USDC)
    MaxHourlyOutflow,                    // Global economic circuit breaker limit
    CurrentHour,                         // Current hour timestamp (u64)
    HourlyOutflowAccumulator,            // Global outflow tracked in current hour (i128)
    ContractHourlyOutflow(Address, u64), // Per-contract outflow tracked in (target, hour) -> i128
    AccumulatedFees,                     // Key: () -> i128 (Protocol fee treasury accumulator)
    Registration(Address),               // Key: Target Contract Address -> VaultConfig
    KeeperNonce(Address),                // Key: Keeper Address -> u64 Highest Redeemed Nonce
    RedeemedVoucher(Address, u64),       // Key: (Keeper Address, Nonce) -> bool consumption marker
}
