use super::*;
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::{Client as TokenClient, StellarAssetClient},
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Vec,
};

struct TestContext<'a> {
    env: Env,
    admin: Address,
    client_user: Address,
    keeper: Address,
    target_contract: Address,
    token_address: Address,
    token_client: TokenClient<'a>,
    vault_address: Address,
    vault_client: LazarusVaultClient<'a>,
    oracle_signing_key: SigningKey,
}

impl<'a> TestContext<'a> {
    fn setup(max_hourly_outflow: i128) -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let client_user = Address::generate(&env);
        let keeper = Address::generate(&env);
        let target_contract = Address::generate(&env);

        // Deterministic 32-byte Ed25519 secret key for the Oracle / FROST signer
        let secret_bytes: [u8; 32] = [42u8; 32];
        let oracle_signing_key = SigningKey::from_bytes(&secret_bytes);
        let oracle_pubkey_bytes = oracle_signing_key.verifying_key().to_bytes();
        let oracle_pubkey = BytesN::from_array(&env, &oracle_pubkey_bytes);

        // Register a native Stellar Asset Contract (SAC) token (e.g. USDC)
        let token_admin = Address::generate(&env);
        let sac = env.register_stellar_asset_contract_v2(token_admin);
        let token_address = sac.address();
        let sac_admin_client = StellarAssetClient::new(&env, &token_address);
        let token_client = TokenClient::new(&env, &token_address);

        // Mint 100,000,000 stroops to client_user
        sac_admin_client.mint(&client_user, &100_000_000i128);

        // Register and initialize LazarusVault
        let vault_address = env.register(LazarusVault, ());
        let vault_client = LazarusVaultClient::new(&env, &vault_address);
        vault_client.initialize(&admin, &oracle_pubkey, &token_address, &max_hourly_outflow);

        Self {
            env,
            admin,
            client_user,
            keeper,
            target_contract,
            token_address,
            token_client,
            vault_address,
            vault_client,
            oracle_signing_key,
        }
    }

    fn sign_voucher(&self, voucher: &BumpVoucher) -> BytesN<64> {
        let mut payload_bytes = Bytes::new(&self.env);
        payload_bytes.append(&Bytes::from_slice(&self.env, b"LAZARUS_VOUCHER_V1"));
        payload_bytes.append(&self.vault_address.clone().to_xdr(&self.env));
        payload_bytes.append(&voucher.keeper.clone().to_xdr(&self.env));
        payload_bytes.append(&voucher.target_contract.clone().to_xdr(&self.env));
        payload_bytes.append(&voucher.ledger_bumped.to_xdr(&self.env));
        payload_bytes.append(&voucher.bounty_amount.to_xdr(&self.env));
        payload_bytes.append(&voucher.nonce.to_xdr(&self.env));

        let digest: BytesN<32> = self.env.crypto().sha256(&payload_bytes).into();
        let digest_arr = digest.to_array();
        let sig = self.oracle_signing_key.sign(&digest_arr);
        BytesN::from_array(&self.env, &sig.to_bytes())
    }
}

#[test]
fn test_initialize_and_double_init_rejected() {
    let ctx = TestContext::setup(50_000_000);
    let pubkey = ctx.vault_client.get_oracle_pubkey();
    assert_eq!(
        pubkey.to_array(),
        ctx.oracle_signing_key.verifying_key().to_bytes()
    );

    let res = ctx
        .vault_client
        .try_initialize(&ctx.admin, &pubkey, &ctx.token_address, &50_000_000);
    assert_eq!(res, Err(Ok(VaultError::AlreadyInitialized)));
}

#[test]
fn test_register_contract_and_overwrite_guard() {
    let ctx = TestContext::setup(50_000_000);

    // Self-registration rejected
    let self_reg = ctx.vault_client.try_register_contract(
        &ctx.client_user,
        &ctx.vault_address,
        &10_000_000,
        &500_000,
        &20_000,
        &500_000,
    );
    assert_eq!(self_reg, Err(Ok(VaultError::InvalidTarget)));

    // Zero deposit or fixed_bounty > MaxHourlyOutflow / 5 rejected
    let bad_deposit = ctx.vault_client.try_register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &0,
        &500_000,
        &20_000,
        &500_000,
    );
    assert_eq!(bad_deposit, Err(Ok(VaultError::BountyOutOfBounds)));

    let excessive_bounty = ctx.vault_client.try_register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &20_000_000,
        &15_000_000, // > 50,000,000 / 5 (10,000,000)
        &20_000,
        &500_000,
    );
    assert_eq!(excessive_bounty, Err(Ok(VaultError::BountyOutOfBounds)));

    // Valid registration
    ctx.vault_client.register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &10_000_000,
        &500_000,
        &20_000,
        &500_000,
    );

    // Audit Fix Verification: Re-registering an already active contract reverts with AlreadyRegistered
    let overwrite_attempt = ctx.vault_client.try_register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &1_000,
        &100,
        &20_000,
        &500_000,
    );
    assert_eq!(overwrite_attempt, Err(Ok(VaultError::AlreadyRegistered)));

    let config = ctx.vault_client.get_registration(&ctx.target_contract);
    assert_eq!(config.balance, 10_000_000);
    assert_eq!(config.policy, BountyPolicy::Fixed(500_000));
    assert!(config.is_active);
    assert_eq!(ctx.token_client.balance(&ctx.vault_address), 10_000_000);
}

#[test]
fn test_deposit_funds_increases_escrow() {
    let ctx = TestContext::setup(50_000_000);
    ctx.vault_client.register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &10_000_000,
        &500_000,
        &20_000,
        &500_000,
    );

    ctx.vault_client
        .deposit_funds(&ctx.client_user, &ctx.target_contract, &5_000_000);
    let config = ctx.vault_client.get_registration(&ctx.target_contract);
    assert_eq!(config.balance, 15_000_000);
    assert_eq!(ctx.token_client.balance(&ctx.vault_address), 15_000_000);
}

#[test]
fn test_record_bump_single_settlement_and_5_percent_fee() {
    let ctx = TestContext::setup(50_000_000);
    ctx.vault_client.register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &10_000_000,
        &1_000_000, // 0.10 USDC (1,000,000 stroops)
        &20_000,
        &500_000,
    );

    let voucher = BumpVoucher {
        keeper: ctx.keeper.clone(),
        target_contract: ctx.target_contract.clone(),
        ledger_bumped: 500_000,
        bounty_amount: 1_000_000,
        nonce: 1,
    };
    let sig = ctx.sign_voucher(&voucher);

    ctx.vault_client.record_bump(&voucher, &sig);

    assert_eq!(ctx.token_client.balance(&ctx.keeper), 1_000_000);
    assert_eq!(ctx.vault_client.get_accumulated_fees(), 50_000);
    assert_eq!(ctx.vault_client.get_keeper_nonce(&ctx.keeper), 1);
    assert!(ctx.vault_client.is_voucher_redeemed(&ctx.keeper, &1));

    let config = ctx.vault_client.get_registration(&ctx.target_contract);
    assert_eq!(config.balance, 10_000_000 - 1_050_000);
}

#[test]
fn test_replay_protection_out_of_order_batch_tolerance_and_strict_billing() {
    let ctx = TestContext::setup(50_000_000);
    ctx.vault_client.register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &10_000_000,
        &1_000_000,
        &20_000,
        &500_000,
    );

    let voucher1 = BumpVoucher {
        keeper: ctx.keeper.clone(),
        target_contract: ctx.target_contract.clone(),
        ledger_bumped: 500_000,
        bounty_amount: 1_000_000,
        nonce: 1,
    };
    let sig1 = ctx.sign_voucher(&voucher1);
    ctx.vault_client.record_bump(&voucher1, &sig1);

    // Replaying already-consumed nonce 1 fails with InvalidNonce
    let replay_res = ctx.vault_client.try_record_bump(&voucher1, &sig1);
    assert_eq!(replay_res, Err(Ok(VaultError::InvalidNonce)));

    // Audit Fix Verification: Skipping nonce 2 (e.g., if voucher #2's target contract was deactivated)
    // and redeeming nonce 3 SUCCEEDS without bricking subsequent vouchers!
    let voucher3 = BumpVoucher {
        nonce: 3,
        ..voucher1.clone()
    };
    let sig3 = ctx.sign_voucher(&voucher3);
    ctx.vault_client.record_bump(&voucher3, &sig3);
    assert_eq!(ctx.vault_client.get_keeper_nonce(&ctx.keeper), 3);
    assert!(ctx.vault_client.is_voucher_redeemed(&ctx.keeper, &3));
    assert!(!ctx.vault_client.is_voucher_redeemed(&ctx.keeper, &2));

    // Bounty mismatch (e.g. 0 or wrong amount) fails with BountyMismatch
    let wrong_bounty = BumpVoucher {
        nonce: 4,
        bounty_amount: 0,
        ..voucher1
    };
    let wrong_sig = ctx.sign_voucher(&wrong_bounty);
    assert_eq!(
        ctx.vault_client.try_record_bump(&wrong_bounty, &wrong_sig),
        Err(Ok(VaultError::BountyMismatch))
    );
}

#[test]
fn test_record_bump_batch_and_limits() {
    let ctx = TestContext::setup(50_000_000);
    ctx.vault_client.register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &50_000_000,
        &1_000_000,
        &20_000,
        &500_000,
    );

    let mut vouchers = Vec::new(&ctx.env);
    let mut signatures = Vec::new(&ctx.env);

    for n in 1..=10u64 {
        let v = BumpVoucher {
            keeper: ctx.keeper.clone(),
            target_contract: ctx.target_contract.clone(),
            ledger_bumped: 500_000 + (n as u32),
            bounty_amount: 1_000_000,
            nonce: n,
        };
        let s = ctx.sign_voucher(&v);
        vouchers.push_back(v);
        signatures.push_back(s);
    }

    ctx.vault_client.record_bump_batch(&vouchers, &signatures);

    assert_eq!(ctx.token_client.balance(&ctx.keeper), 10_000_000);
    assert_eq!(ctx.vault_client.get_accumulated_fees(), 500_000);
    assert_eq!(ctx.vault_client.get_keeper_nonce(&ctx.keeper), 10);

    // Vector mismatch check
    let mut mismatched_sigs = Vec::new(&ctx.env);
    mismatched_sigs.push_back(signatures.get(0).unwrap());
    assert_eq!(
        ctx.vault_client
            .try_record_bump_batch(&vouchers, &mismatched_sigs),
        Err(Ok(VaultError::VectorMismatch))
    );

    // Batch size > 10 rejected
    let v11 = BumpVoucher {
        keeper: ctx.keeper.clone(),
        target_contract: ctx.target_contract.clone(),
        ledger_bumped: 500_011,
        bounty_amount: 1_000_000,
        nonce: 11,
    };
    vouchers.push_back(v11.clone());
    signatures.push_back(ctx.sign_voucher(&v11));
    assert_eq!(
        ctx.vault_client
            .try_record_bump_batch(&vouchers, &signatures),
        Err(Ok(VaultError::BatchSizeExceeded))
    );
}

#[test]
fn test_hourly_outflow_circuit_breaker_and_hour_rollover() {
    // Global MaxHourlyOutflow = 6,000,000; per-contract cap = max(3,000,000, 2 * 1,000,000) = 3,000,000
    let ctx = TestContext::setup(6_000_000);
    ctx.env.ledger().with_mut(|li| {
        li.timestamp = 3600 * 10; // Hour 10
    });

    ctx.vault_client.register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &10_000_000,
        &1_000_000, // 1,050,000 with 5% fee
        &20_000,
        &500_000,
    );

    let v1 = BumpVoucher {
        keeper: ctx.keeper.clone(),
        target_contract: ctx.target_contract.clone(),
        ledger_bumped: 500_000,
        bounty_amount: 1_000_000,
        nonce: 1,
    };
    ctx.vault_client.record_bump(&v1, &ctx.sign_voucher(&v1));

    let v2 = BumpVoucher {
        nonce: 2,
        ..v1.clone()
    };
    ctx.vault_client.record_bump(&v2, &ctx.sign_voucher(&v2));

    // Third voucher for the same contract in the same hour brings contract outflow to
    // 3,150,000 > 3,000,000 (per-contract hourly cap), reverting with HourlyOutflowExceeded
    let v3 = BumpVoucher {
        nonce: 3,
        ..v1.clone()
    };
    let v3_sig = ctx.sign_voucher(&v3);
    assert_eq!(
        ctx.vault_client.try_record_bump(&v3, &v3_sig),
        Err(Ok(VaultError::HourlyOutflowExceeded))
    );

    // Advance ledger timestamp by 1 hour -> circuit breaker resets
    ctx.env.ledger().with_mut(|li| {
        li.timestamp = 3600 * 11;
    });
    ctx.vault_client.record_bump(&v3, &v3_sig);
    assert_eq!(ctx.vault_client.get_keeper_nonce(&ctx.keeper), 3);
}

#[test]
fn test_emergency_withdraw_and_protocol_fee_withdrawal() {
    let ctx = TestContext::setup(50_000_000);
    ctx.vault_client.register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &10_000_000,
        &1_000_000,
        &20_000,
        &500_000,
    );

    let v1 = BumpVoucher {
        keeper: ctx.keeper.clone(),
        target_contract: ctx.target_contract.clone(),
        ledger_bumped: 500_000,
        bounty_amount: 1_000_000,
        nonce: 1,
    };
    ctx.vault_client.record_bump(&v1, &ctx.sign_voucher(&v1));

    // Unauthorized user cannot withdraw protocol fees
    let treasury = Address::generate(&ctx.env);
    assert_eq!(
        ctx.vault_client
            .try_withdraw_protocol_fees(&ctx.client_user, &treasury, &50_000),
        Err(Ok(VaultError::Unauthorized))
    );

    // Admin withdraws accumulated 50,000 protocol fees
    ctx.vault_client
        .withdraw_protocol_fees(&ctx.admin, &treasury, &50_000);
    assert_eq!(ctx.token_client.balance(&treasury), 50_000);
    assert_eq!(ctx.vault_client.get_accumulated_fees(), 0);

    // Emergency withdraw by depositor refunds remaining 8,950,000 and marks contract inactive
    ctx.vault_client
        .emergency_withdraw(&ctx.client_user, &ctx.target_contract);
    let config = ctx.vault_client.get_registration(&ctx.target_contract);
    assert_eq!(config.balance, 0);
    assert!(!config.is_active);
    assert_eq!(ctx.token_client.balance(&ctx.vault_address), 0);
}

#[test]
fn test_admin_update_oracle_pubkey_and_max_hourly_outflow() {
    let ctx = TestContext::setup(50_000_000);

    // Non-admin cannot rotate oracle key or max hourly outflow
    let new_secret: [u8; 32] = [99u8; 32];
    let new_signing_key = SigningKey::from_bytes(&new_secret);
    let new_pubkey = BytesN::from_array(&ctx.env, &new_signing_key.verifying_key().to_bytes());

    assert_eq!(
        ctx.vault_client
            .try_update_oracle_pubkey(&ctx.client_user, &new_pubkey),
        Err(Ok(VaultError::Unauthorized))
    );
    assert_eq!(
        ctx.vault_client
            .try_update_max_hourly_outflow(&ctx.client_user, &80_000_000),
        Err(Ok(VaultError::Unauthorized))
    );
    assert_eq!(
        ctx.vault_client
            .try_update_max_hourly_outflow(&ctx.admin, &0),
        Err(Ok(VaultError::BountyOutOfBounds))
    );

    // Admin rotates oracle key (e.g. v1 Nitro Enclave -> Milestone 2 2-of-3 FROST MPC group key)
    ctx.vault_client
        .update_oracle_pubkey(&ctx.admin, &new_pubkey);
    assert_eq!(ctx.vault_client.get_oracle_pubkey(), new_pubkey);

    // Admin updates max hourly outflow ceiling
    ctx.vault_client
        .update_max_hourly_outflow(&ctx.admin, &80_000_000);
    let (_hour, _acc, max_outflow) = ctx.vault_client.get_hourly_outflow();
    assert_eq!(max_outflow, 80_000_000);
}

#[test]
fn test_reactivate_after_emergency_withdraw_and_third_party_rejected() {
    let ctx = TestContext::setup(50_000_000);
    ctx.vault_client.register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &10_000_000,
        &1_000_000,
        &20_000,
        &500_000,
    );

    // Client performs emergency withdrawal, deactivating contract
    ctx.vault_client
        .emergency_withdraw(&ctx.client_user, &ctx.target_contract);
    let config = ctx.vault_client.get_registration(&ctx.target_contract);
    assert!(!config.is_active);
    assert_eq!(config.balance, 0);

    // Third party attempting to deposit into inactive contract is rejected
    let third_party = Address::generate(&ctx.env);
    let sac_admin_client = StellarAssetClient::new(&ctx.env, &ctx.token_address);
    sac_admin_client.mint(&third_party, &5_000_000i128);

    let res_third_party =
        ctx.vault_client
            .try_deposit_funds(&third_party, &ctx.target_contract, &2_000_000);
    assert_eq!(res_third_party, Err(Ok(VaultError::ContractInactive)));

    // Original client deposits new escrow funds, successfully reactivating the contract
    ctx.vault_client
        .deposit_funds(&ctx.client_user, &ctx.target_contract, &5_000_000);
    let reactivated = ctx.vault_client.get_registration(&ctx.target_contract);
    assert!(reactivated.is_active);
    assert_eq!(reactivated.balance, 5_000_000);

    // Third party attempting to deposit into ACTIVE contract is rejected with Unauthorized
    let res_active_third_party =
        ctx.vault_client
            .try_deposit_funds(&third_party, &ctx.target_contract, &1_000_000);
    assert_eq!(res_active_third_party, Err(Ok(VaultError::Unauthorized)));

    // Deactivate again via emergency_withdraw and verify a third party cannot hijack ownership via register_contract
    ctx.vault_client
        .emergency_withdraw(&ctx.client_user, &ctx.target_contract);
    let hijack_attempt = ctx.vault_client.try_register_contract(
        &third_party,
        &ctx.target_contract,
        &1_000_000,
        &100_000,
        &20_000,
        &500_000,
    );
    assert_eq!(hijack_attempt, Err(Ok(VaultError::Unauthorized)));
}

#[test]
fn test_threshold_bounds_and_empty_batch_rejected() {
    let ctx = TestContext::setup(50_000_000);

    // min_threshold < 100 rejected
    assert_eq!(
        ctx.vault_client.try_register_contract(
            &ctx.client_user,
            &ctx.target_contract,
            &10_000_000,
            &500_000,
            &50,
            &500_000,
        ),
        Err(Ok(VaultError::BountyOutOfBounds))
    );

    // bump_target <= min_threshold rejected
    assert_eq!(
        ctx.vault_client.try_register_contract(
            &ctx.client_user,
            &ctx.target_contract,
            &10_000_000,
            &500_000,
            &20_000,
            &20_000,
        ),
        Err(Ok(VaultError::BountyOutOfBounds))
    );

    // bump_target > MAX_TTL_LEDGERS (3,110,400) rejected
    assert_eq!(
        ctx.vault_client.try_register_contract(
            &ctx.client_user,
            &ctx.target_contract,
            &10_000_000,
            &500_000,
            &20_000,
            &(MAX_TTL_LEDGERS + 1),
        ),
        Err(Ok(VaultError::BountyOutOfBounds))
    );

    // Empty batch rejected with VectorMismatch
    let empty_vouchers: Vec<BumpVoucher> = Vec::new(&ctx.env);
    let empty_sigs: Vec<BytesN<64>> = Vec::new(&ctx.env);
    assert_eq!(
        ctx.vault_client
            .try_record_bump_batch(&empty_vouchers, &empty_sigs),
        Err(Ok(VaultError::VectorMismatch))
    );

    // Registering the payment token itself as a target contract is rejected with InvalidTarget
    assert_eq!(
        ctx.vault_client.try_register_contract(
            &ctx.client_user,
            &ctx.token_address,
            &10_000_000,
            &500_000,
            &20_000,
            &500_000,
        ),
        Err(Ok(VaultError::InvalidTarget))
    );

    // Zero-ledger voucher (ledger_bumped == 0) is rejected with BountyOutOfBounds
    ctx.vault_client.register_contract(
        &ctx.client_user,
        &ctx.target_contract,
        &10_000_000,
        &500_000,
        &20_000,
        &500_000,
    );
    let zero_ledger_voucher = BumpVoucher {
        keeper: ctx.keeper.clone(),
        target_contract: ctx.target_contract.clone(),
        ledger_bumped: 0,
        bounty_amount: 500_000,
        nonce: 1,
    };
    let zero_sig = ctx.sign_voucher(&zero_ledger_voucher);
    assert_eq!(
        ctx.vault_client
            .try_record_bump(&zero_ledger_voucher, &zero_sig),
        Err(Ok(VaultError::BountyOutOfBounds))
    );
}
