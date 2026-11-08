use crate::types::*;
use soroban_sdk::{contract, contractimpl, token, xdr::ToXdr, Address, Bytes, BytesN, Env, Vec};

#[contract]
pub struct LazarusVault;

#[contractimpl]
impl LazarusVault {
    /// Atomic CAP-0058 constructor executed inside `CreateContractWithCtorHostFunction`.
    /// Eliminates any multi-transaction deployment initialization window.
    pub fn __constructor(
        e: Env,
        admin: Address,
        oracle_pubkey: BytesN<32>,
        token: Address,
        max_hourly_outflow: i128,
    ) -> Result<(), VaultError> {
        Self::initialize(e, admin, oracle_pubkey, token, max_hourly_outflow)
    }

    /// Initializes administrative keys, oracle public key, and payment token.
    /// Requires `admin.require_auth()` and rejects re-initialization (`AlreadyInitialized`).
    pub fn initialize(
        e: Env,
        admin: Address,
        oracle_pubkey: BytesN<32>,
        token: Address,
        max_hourly_outflow: i128,
    ) -> Result<(), VaultError> {
        if e.storage().instance().has(&DataKey::Admin) {
            return Err(VaultError::AlreadyInitialized);
        }
        admin.require_auth();
        if token == e.current_contract_address() {
            return Err(VaultError::InvalidTarget);
        }
        if max_hourly_outflow <= 0 {
            return Err(VaultError::BountyOutOfBounds);
        }

        e.storage().instance().set(&DataKey::Admin, &admin);
        e.storage()
            .instance()
            .set(&DataKey::OraclePubKey, &oracle_pubkey);
        e.storage().instance().set(&DataKey::Token, &token);
        e.storage()
            .instance()
            .set(&DataKey::MaxHourlyOutflow, &max_hourly_outflow);
        e.storage().instance().set(&DataKey::CurrentHour, &0u64);
        e.storage()
            .instance()
            .set(&DataKey::HourlyOutflowAccumulator, &0i128);
        e.storage()
            .instance()
            .set(&DataKey::AccumulatedFees, &0i128);

        e.storage().instance().extend_ttl(BUMP_THRESHOLD, BUMP_TO);
        Ok(())
    }

    /// Registers a client contract with an initial escrow deposit.
    /// Includes an existence guard (`VaultError::AlreadyRegistered`) to prevent malicious
    /// registration overwrites from trapping existing client escrow balances, and caps
    /// `fixed_bounty` relative to `MaxHourlyOutflow` to prevent cross-protocol griefing.
    pub fn register_contract(
        e: Env,
        client: Address,
        target: Address,
        initial_deposit: i128,
        fixed_bounty: i128,
        min_threshold: u32,
        bump_target: u32,
    ) -> Result<(), VaultError> {
        client.require_auth();
        if target == e.current_contract_address() {
            return Err(VaultError::InvalidTarget);
        }
        if initial_deposit <= 0 || fixed_bounty <= 0 {
            return Err(VaultError::BountyOutOfBounds);
        }
        if min_threshold < MIN_THRESHOLD_LEDGERS
            || bump_target <= min_threshold
            || bump_target > MAX_TTL_LEDGERS
        {
            return Err(VaultError::BountyOutOfBounds);
        }

        let max_hourly: i128 = e
            .storage()
            .instance()
            .get(&DataKey::MaxHourlyOutflow)
            .ok_or(VaultError::NotInitialized)?;

        // Audit Mitigation: Cap single fixed_bounty at 20% of global MaxHourlyOutflow
        // so a single malicious registration cannot exhaust 100% of the global circuit breaker in one bump.
        if fixed_bounty > (max_hourly / 5) {
            return Err(VaultError::BountyOutOfBounds);
        }

        // Audit Mitigation: Existence & Ownership Hijack Guard
        // Prevents overwriting active/funded registrations and prevents a third-party attacker
        // from hijacking `config.client` after the legitimate owner calls `emergency_withdraw`.
        if let Some(existing) = e
            .storage()
            .persistent()
            .get::<DataKey, VaultConfig>(&DataKey::Registration(target.clone()))
        {
            if existing.is_active || existing.balance > 0 {
                return Err(VaultError::AlreadyRegistered);
            }
            if existing.client != client {
                return Err(VaultError::Unauthorized);
            }
        }

        let token_addr: Address = e
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(VaultError::NotInitialized)?;
        if target == token_addr {
            return Err(VaultError::InvalidTarget);
        }
        let token_client = token::Client::new(&e, &token_addr);

        // Transfer funds from client to vault
        token_client.transfer(&client, e.current_contract_address(), &initial_deposit);

        // Per-contract hourly outflow cap: at most 50% of global MaxHourlyOutflow per hour
        let max_contract_hourly_outflow = core::cmp::max(max_hourly / 2, fixed_bounty * 2);

        let config = VaultConfig {
            client: client.clone(),
            balance: initial_deposit,
            policy: BountyPolicy::Fixed(fixed_bounty),
            min_ledger_threshold: min_threshold,
            bump_target,
            max_contract_hourly_outflow,
            is_active: true,
        };

        e.storage()
            .persistent()
            .set(&DataKey::Registration(target.clone()), &config);
        e.storage().persistent().extend_ttl(
            &DataKey::Registration(target.clone()),
            BUMP_THRESHOLD,
            BUMP_TO,
        );
        e.storage().instance().extend_ttl(BUMP_THRESHOLD, BUMP_TO);

        ContractRegistered {
            target,
            client,
            initial_deposit,
            fixed_bounty,
        }
        .publish(&e);
        Ok(())
    }

    /// Deposits additional escrow funds for an existing registered contract
    pub fn deposit_funds(
        e: Env,
        client: Address,
        target: Address,
        amount: i128,
    ) -> Result<(), VaultError> {
        client.require_auth();
        if amount <= 0 {
            return Err(VaultError::BountyOutOfBounds);
        }

        let mut config: VaultConfig = e
            .storage()
            .persistent()
            .get(&DataKey::Registration(target.clone()))
            .ok_or(VaultError::ContractInactive)?;

        // Escrow Client Authority Guard & Anti-Trapping:
        // Only the registered client who owns the vault escrow may deposit funds.
        // Third-party deposits are rejected to prevent an attacker from pre-registering a target
        // and stealing third-party deposits via emergency_withdraw.
        if client != config.client {
            if !config.is_active {
                return Err(VaultError::ContractInactive);
            }
            return Err(VaultError::Unauthorized);
        }
        if !config.is_active {
            config.is_active = true;
        }

        let token_addr: Address = e
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(VaultError::NotInitialized)?;
        if target == token_addr {
            return Err(VaultError::InvalidTarget);
        }
        let token_client = token::Client::new(&e, &token_addr);
        token_client.transfer(&client, e.current_contract_address(), &amount);

        config.balance = config
            .balance
            .checked_add(amount)
            .ok_or(VaultError::ArithmeticError)?;

        e.storage()
            .persistent()
            .set(&DataKey::Registration(target.clone()), &config);
        e.storage().persistent().extend_ttl(
            &DataKey::Registration(target.clone()),
            BUMP_THRESHOLD,
            BUMP_TO,
        );
        e.storage().instance().extend_ttl(BUMP_THRESHOLD, BUMP_TO);

        FundsDeposited {
            target,
            client,
            amount,
            new_balance: config.balance,
        }
        .publish(&e);
        Ok(())
    }

    /// Redeems a single attestation voucher and dispatches bounty
    pub fn record_bump(
        e: Env,
        voucher: BumpVoucher,
        signature: BytesN<64>,
    ) -> Result<(), VaultError> {
        voucher.keeper.require_auth();
        Self::process_voucher(&e, &voucher, &signature)?;
        e.storage().instance().extend_ttl(BUMP_THRESHOLD, BUMP_TO);
        Ok(())
    }

    /// Redeems a batch of up to 10 vouchers in a single transaction
    pub fn record_bump_batch(
        e: Env,
        vouchers: Vec<BumpVoucher>,
        signatures: Vec<BytesN<64>>,
    ) -> Result<(), VaultError> {
        let len = vouchers.len();
        if len == 0 {
            return Err(VaultError::VectorMismatch);
        }
        if len > MAX_BATCH_SIZE {
            return Err(VaultError::BatchSizeExceeded);
        }
        if len != signatures.len() {
            return Err(VaultError::VectorMismatch);
        }

        // Authorize each keeper in the batch once (avoiding duplicate require_auth in same frame)
        let mut authorized_keepers: Vec<Address> = Vec::new(&e);
        for i in 0..len {
            let k = vouchers.get(i).unwrap().keeper;
            if !authorized_keepers.contains(&k) {
                k.require_auth();
                authorized_keepers.push_back(k);
            }
        }

        for i in 0..len {
            let voucher = vouchers.get(i).unwrap();
            let sig = signatures.get(i).unwrap();
            Self::process_voucher(&e, &voucher, &sig)?;
        }

        e.storage().instance().extend_ttl(BUMP_THRESHOLD, BUMP_TO);
        Ok(())
    }

    /// Emergency withdrawal of unspent escrow balance by contract depositor
    pub fn emergency_withdraw(e: Env, client: Address, target: Address) -> Result<(), VaultError> {
        client.require_auth();

        let mut config: VaultConfig = e
            .storage()
            .persistent()
            .get(&DataKey::Registration(target.clone()))
            .ok_or(VaultError::ContractInactive)?;

        if config.client != client {
            return Err(VaultError::Unauthorized);
        }

        let refund = config.balance;
        config.balance = 0;
        config.is_active = false;

        // Zero-Refund Edge Case Guard: Avoid 0-amount token transfer calls
        if refund > 0 {
            let token_addr: Address = e
                .storage()
                .instance()
                .get(&DataKey::Token)
                .ok_or(VaultError::NotInitialized)?;
            let token_client = token::Client::new(&e, &token_addr);
            token_client.transfer(&e.current_contract_address(), &client, &refund);
        }

        e.storage()
            .persistent()
            .set(&DataKey::Registration(target.clone()), &config);
        e.storage().persistent().extend_ttl(
            &DataKey::Registration(target.clone()),
            BUMP_THRESHOLD,
            BUMP_TO,
        );
        e.storage().instance().extend_ttl(BUMP_THRESHOLD, BUMP_TO);

        EmergencyWithdrawn {
            target,
            client,
            refund,
        }
        .publish(&e);
        Ok(())
    }

    /// Withdraws accumulated protocol fees by authorized administrator
    pub fn withdraw_protocol_fees(
        e: Env,
        admin: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), VaultError> {
        admin.require_auth();
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VaultError::NotInitialized)?;
        if admin != stored_admin {
            return Err(VaultError::Unauthorized);
        }

        let mut accumulated: i128 = e
            .storage()
            .instance()
            .get(&DataKey::AccumulatedFees)
            .unwrap_or(0);
        if amount > accumulated || amount <= 0 {
            return Err(VaultError::BountyOutOfBounds);
        }

        accumulated = accumulated
            .checked_sub(amount)
            .ok_or(VaultError::ArithmeticError)?;
        e.storage()
            .instance()
            .set(&DataKey::AccumulatedFees, &accumulated);

        let token_addr: Address = e
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(VaultError::NotInitialized)?;
        if to == e.current_contract_address() {
            return Err(VaultError::InvalidTarget);
        }
        let token_client = token::Client::new(&e, &token_addr);
        token_client.transfer(&e.current_contract_address(), &to, &amount);

        e.storage().instance().extend_ttl(BUMP_THRESHOLD, BUMP_TO);

        ProtocolFeesWithdrawn { admin, to, amount }.publish(&e);
        Ok(())
    }

    /// Rotates the Oracle / FROST group public key (e.g., migrating from Nitro Enclave to 2-of-3 FROST MPC)
    pub fn update_oracle_pubkey(
        e: Env,
        admin: Address,
        new_oracle_pubkey: BytesN<32>,
    ) -> Result<(), VaultError> {
        admin.require_auth();
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VaultError::NotInitialized)?;
        if admin != stored_admin {
            return Err(VaultError::Unauthorized);
        }

        e.storage()
            .instance()
            .set(&DataKey::OraclePubKey, &new_oracle_pubkey);
        e.storage().instance().extend_ttl(BUMP_THRESHOLD, BUMP_TO);

        OraclePubKeyRotated {
            admin,
            new_oracle_pubkey,
        }
        .publish(&e);
        Ok(())
    }

    /// Updates the hourly outflow circuit breaker ceiling
    pub fn update_max_hourly_outflow(
        e: Env,
        admin: Address,
        new_max_outflow: i128,
    ) -> Result<(), VaultError> {
        admin.require_auth();
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VaultError::NotInitialized)?;
        if admin != stored_admin {
            return Err(VaultError::Unauthorized);
        }
        if new_max_outflow <= 0 {
            return Err(VaultError::BountyOutOfBounds);
        }

        e.storage()
            .instance()
            .set(&DataKey::MaxHourlyOutflow, &new_max_outflow);
        e.storage().instance().extend_ttl(BUMP_THRESHOLD, BUMP_TO);

        MaxHourlyOutflowUpdated {
            admin,
            new_max_outflow,
        }
        .publish(&e);
        Ok(())
    }

    /// Read-only query: Fetches VaultConfig for an enrolled target contract
    pub fn get_registration(e: Env, target: Address) -> Result<VaultConfig, VaultError> {
        e.storage()
            .persistent()
            .get(&DataKey::Registration(target))
            .ok_or(VaultError::ContractInactive)
    }

    /// Read-only query: Fetches highest redeemed nonce for a keeper address
    pub fn get_keeper_nonce(e: Env, keeper: Address) -> u64 {
        e.storage()
            .persistent()
            .get(&DataKey::KeeperNonce(keeper))
            .unwrap_or(0u64)
    }

    /// Read-only query: Checks whether a specific (keeper, nonce) voucher has been redeemed
    pub fn is_voucher_redeemed(e: Env, keeper: Address, nonce: u64) -> bool {
        e.storage()
            .persistent()
            .get(&DataKey::RedeemedVoucher(keeper, nonce))
            .unwrap_or(false)
    }

    /// Read-only query: Fetches accumulated 5% protocol fees
    pub fn get_accumulated_fees(e: Env) -> i128 {
        e.storage()
            .instance()
            .get(&DataKey::AccumulatedFees)
            .unwrap_or(0i128)
    }

    /// Read-only query: Fetches (current_hour, hourly_outflow_accumulator, max_hourly_outflow)
    pub fn get_hourly_outflow(e: Env) -> (u64, i128, i128) {
        let hour = e
            .storage()
            .instance()
            .get(&DataKey::CurrentHour)
            .unwrap_or(0u64);
        let acc = e
            .storage()
            .instance()
            .get(&DataKey::HourlyOutflowAccumulator)
            .unwrap_or(0i128);
        let max = e
            .storage()
            .instance()
            .get(&DataKey::MaxHourlyOutflow)
            .unwrap_or(0i128);
        (hour, acc, max)
    }

    /// Read-only query: Fetches the active Oracle / FROST public key
    pub fn get_oracle_pubkey(e: Env) -> Result<BytesN<32>, VaultError> {
        e.storage()
            .instance()
            .get(&DataKey::OraclePubKey)
            .ok_or(VaultError::NotInitialized)
    }

    /// Internal settlement engine
    fn process_voucher(
        e: &Env,
        voucher: &BumpVoucher,
        signature: &BytesN<64>,
    ) -> Result<(), VaultError> {
        let oracle_pubkey: BytesN<32> = e
            .storage()
            .instance()
            .get(&DataKey::OraclePubKey)
            .ok_or(VaultError::NotInitialized)?;

        // 1. Replay Safety & Out-of-Order Batch Tolerance (Audit Remediation):
        // Uses per-voucher consumption marker `DataKey::RedeemedVoucher(keeper, nonce)` so that if a
        // keeper skips an unredeemable voucher (e.g., voucher #3 whose target contract called
        // emergency_withdraw), vouchers #4..#10 remain valid and redeemable without batch deadlocks.
        if voucher.nonce == 0 {
            return Err(VaultError::InvalidNonce);
        }
        if voucher.ledger_bumped == 0 {
            return Err(VaultError::BountyOutOfBounds);
        }
        let redeemed_key = DataKey::RedeemedVoucher(voucher.keeper.clone(), voucher.nonce);
        if e.storage().persistent().get(&redeemed_key).unwrap_or(false) {
            return Err(VaultError::InvalidNonce);
        }

        // 2. Load Contract Configuration
        let mut config: VaultConfig = e
            .storage()
            .persistent()
            .get(&DataKey::Registration(voucher.target_contract.clone()))
            .ok_or(VaultError::ContractInactive)?;

        if !config.is_active {
            return Err(VaultError::ContractInactive);
        }

        // 3. Strict Billing Invariant: Enforce exact match to prevent zero-bounties
        match config.policy {
            BountyPolicy::Fixed(expected) => {
                if voucher.bounty_amount != expected {
                    return Err(VaultError::BountyMismatch);
                }
            }
        }

        // 4. Cryptographic Verification with Domain Separation & Replay Prevention
        let mut payload_bytes = Bytes::new(e);
        payload_bytes.append(&Bytes::from_slice(e, b"LAZARUS_VOUCHER_V1"));
        payload_bytes.append(&e.current_contract_address().to_xdr(e));
        payload_bytes.append(&voucher.keeper.clone().to_xdr(e));
        payload_bytes.append(&voucher.target_contract.clone().to_xdr(e));
        payload_bytes.append(&voucher.ledger_bumped.to_xdr(e));
        payload_bytes.append(&voucher.bounty_amount.to_xdr(e));
        payload_bytes.append(&voucher.nonce.to_xdr(e));

        let digest: BytesN<32> = e.crypto().sha256(&payload_bytes).into();
        // Host verification: ed25519_verify traps/panics directly at the host VM level on verification failure.
        e.crypto()
            .ed25519_verify(&oracle_pubkey, &digest.into(), signature);

        // 5. Calculate 5% protocol fee surcharge
        let protocol_fee = voucher
            .bounty_amount
            .checked_mul(PROTOCOL_FEE_BPS)
            .ok_or(VaultError::ArithmeticError)?
            .checked_div(BPS_DENOMINATOR)
            .ok_or(VaultError::ArithmeticError)?;

        let total_deduction = voucher
            .bounty_amount
            .checked_add(protocol_fee)
            .ok_or(VaultError::ArithmeticError)?;

        if config.balance < total_deduction {
            return Err(VaultError::InsufficientEscrow);
        }

        // 6. Enforce Global & Per-Contract Hourly Outflow Circuit Breakers (Checks before Effects)
        Self::check_hourly_outflow(
            e,
            &voucher.target_contract,
            config.max_contract_hourly_outflow,
            total_deduction,
        )?;

        // 7. Track accumulated protocol fees for administrative treasury withdrawal (Effects)
        let accumulated_fees: i128 = e
            .storage()
            .instance()
            .get(&DataKey::AccumulatedFees)
            .unwrap_or(0);
        e.storage().instance().set(
            &DataKey::AccumulatedFees,
            &accumulated_fees
                .checked_add(protocol_fee)
                .ok_or(VaultError::ArithmeticError)?,
        );

        // 8. Update Escrow Balance, Voucher Consumption Marker, Highest Nonce & Persistent TTLs (Effects)
        config.balance = config
            .balance
            .checked_sub(total_deduction)
            .ok_or(VaultError::ArithmeticError)?;

        e.storage().persistent().set(
            &DataKey::Registration(voucher.target_contract.clone()),
            &config,
        );
        e.storage().persistent().extend_ttl(
            &DataKey::Registration(voucher.target_contract.clone()),
            BUMP_THRESHOLD,
            BUMP_TO,
        );

        e.storage().persistent().set(&redeemed_key, &true);
        e.storage()
            .persistent()
            .extend_ttl(&redeemed_key, BUMP_THRESHOLD, BUMP_TO);

        let prev_max_nonce: u64 = e
            .storage()
            .persistent()
            .get(&DataKey::KeeperNonce(voucher.keeper.clone()))
            .unwrap_or(0u64);
        let new_max_nonce = core::cmp::max(prev_max_nonce, voucher.nonce);
        e.storage().persistent().set(
            &DataKey::KeeperNonce(voucher.keeper.clone()),
            &new_max_nonce,
        );
        e.storage().persistent().extend_ttl(
            &DataKey::KeeperNonce(voucher.keeper.clone()),
            BUMP_THRESHOLD,
            BUMP_TO,
        );

        // 9. Execute Token Payout to Keeper via SAC Client (Interactions)
        let token_addr: Address = e
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(VaultError::NotInitialized)?;
        let token_client = token::Client::new(e, &token_addr);
        token_client.transfer(
            &e.current_contract_address(),
            &voucher.keeper,
            &voucher.bounty_amount,
        );

        BumpRecorded {
            keeper: voucher.keeper.clone(),
            target_contract: voucher.target_contract.clone(),
            nonce: voucher.nonce,
            bounty_amount: voucher.bounty_amount,
            protocol_fee,
        }
        .publish(e);

        Ok(())
    }

    /// Validates and updates both per-contract and global hourly outflow limits atomically
    fn check_hourly_outflow(
        e: &Env,
        target_contract: &Address,
        max_contract_hourly: i128,
        amount: i128,
    ) -> Result<(), VaultError> {
        let current_timestamp = e.ledger().timestamp();
        let current_hour = current_timestamp / 3600;

        let tracked_hour: u64 = e
            .storage()
            .instance()
            .get(&DataKey::CurrentHour)
            .unwrap_or(0);
        let current_accumulator: i128 = e
            .storage()
            .instance()
            .get(&DataKey::HourlyOutflowAccumulator)
            .unwrap_or(0);
        let max_hourly: i128 = e
            .storage()
            .instance()
            .get(&DataKey::MaxHourlyOutflow)
            .unwrap_or(i128::MAX);

        let is_new_hour = current_hour > tracked_hour;
        let new_global_accumulator = if is_new_hour {
            amount
        } else {
            current_accumulator
                .checked_add(amount)
                .ok_or(VaultError::ArithmeticError)?
        };

        // Per-contract hourly outflow check (clamped dynamically to global max_hourly)
        let effective_contract_cap = core::cmp::min(max_contract_hourly, max_hourly);
        let contract_hour_key =
            DataKey::ContractHourlyOutflow(target_contract.clone(), current_hour);
        let current_contract_outflow: i128 = e
            .storage()
            .persistent()
            .get(&contract_hour_key)
            .unwrap_or(0i128);
        let new_contract_outflow = current_contract_outflow
            .checked_add(amount)
            .ok_or(VaultError::ArithmeticError)?;

        if new_contract_outflow > effective_contract_cap || new_global_accumulator > max_hourly {
            return Err(VaultError::HourlyOutflowExceeded);
        }

        // Commit state updates after all checks pass
        if is_new_hour {
            e.storage()
                .instance()
                .set(&DataKey::CurrentHour, &current_hour);
        }
        e.storage()
            .instance()
            .set(&DataKey::HourlyOutflowAccumulator, &new_global_accumulator);
        e.storage()
            .persistent()
            .set(&contract_hour_key, &new_contract_outflow);
        e.storage()
            .persistent()
            .extend_ttl(&contract_hour_key, BUMP_THRESHOLD, BUMP_TO);
        Ok(())
    }
}
