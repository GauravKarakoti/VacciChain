#![no_std]

mod storage;
mod events;
mod mint;
mod verify;

use soroban_sdk::{contract, contracterror, contractimpl, Address, BytesN, Env, String, Vec};
use storage::{hash_address, DataKey, IssuerRecord, VaccinationRecord};

/// Contract errors.
///
/// | Code | Name             | Description                                      |
/// |------|------------------|--------------------------------------------------|
/// | 1    | AlreadyInitialized | Contract has already been initialized           |
/// | 2    | NotInitialized   | Contract has not been initialized                |
/// | 3    | Unauthorized     | Caller is not an authorized issuer               |
/// | 4    | ProposalExpired  | Admin transfer proposal has expired              |
/// | 5    | NoPendingTransfer | No pending admin transfer exists                |
/// | 6    | DuplicateRecord              | Identical vaccination record already exists      |
/// | 7    | RecordNotFound               | Vaccination record does not exist                |
/// | 8    | AlreadyRevoked               | Vaccination record is already revoked           |
/// | 9    | InvalidInput                 | Input failed validation at the contract boundary |
/// | 10   | InvalidInputVaccineName      | vaccine_name exceeds maximum length             |
/// | 11   | InvalidInputDateAdministered | date_administered exceeds maximum length        |
/// | 12   | InvalidInputIssuerName       | issuer name exceeds maximum length              |
/// | 13   | InvalidInputLicense          | issuer license exceeds maximum length           |
/// | 14   | InvalidInputCountry          | issuer country exceeds maximum length           |
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    ProposalExpired = 4,
    NoPendingTransfer = 5,
    DuplicateRecord = 6,
    RecordNotFound = 7,
    AlreadyRevoked = 8,
    InvalidInput = 9,
    InvalidInputVaccineName = 10,
    InvalidInputDateAdministered = 11,
    InvalidInputIssuerName = 12,
    InvalidInputLicense = 13,
    InvalidInputCountry = 14,
}

const MAX_STRING_LENGTH: u32 = 100;

fn validate_input_length(field: &String, field_name: &str) -> Result<(), ContractError> {
    if field.len() > MAX_STRING_LENGTH {
        return Err(match field_name {
            "vaccine_name" => ContractError::InvalidInputVaccineName,
            "date_administered" => ContractError::InvalidInputDateAdministered,
            "name" => ContractError::InvalidInputIssuerName,
            "license" => ContractError::InvalidInputLicense,
            "country" => ContractError::InvalidInputCountry,
            _ => ContractError::InvalidInput,
        });
    }
    Ok(())
}

#[contract]
pub struct VacciChainContract;

#[contractimpl]
impl VacciChainContract {
    /// Initialize contract with an admin address
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&DataKey::Initialized) {
            return Err(ContractError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Initialized, &true);
        env.storage().persistent().set(&DataKey::Admin, &admin);
        Ok(())
    }

    /// Admin: authorize a new issuer with metadata
    pub fn add_issuer(
        env: Env,
        issuer: Address,
        name: String,
        license: String,
        country: String,
    ) -> Result<(), ContractError> {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).expect("not initialized");
        admin.require_auth();
        let issuer_key = hash_address(&env, &issuer);
        env.storage().persistent().set(&DataKey::Issuer(issuer_key.clone()), &true);

        validate_input_length(&name, "name")?;
        validate_input_length(&license, "license")?;
        validate_input_length(&country, "country")?;

        let record = IssuerRecord {
            name,
            license,
            country,
            authorized: true,
        };

        env.storage().persistent().set(&DataKey::IssuerMeta(issuer_key.clone()), &record);

        let mut issuers: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::IssuerList)
            .unwrap_or(Vec::new(&env));
        let mut exists = false;
        for i in 0..issuers.len() {
            if issuers.get(i).unwrap() == issuer {
                exists = true;
                break;
            }
        }
        if !exists {
            issuers.push_back(issuer.clone());
            env.storage().persistent().set(&DataKey::IssuerList, &issuers);
        }
        events::emit_issuer_added(&env, &issuer, &admin);
        Ok(())
    }

    /// Public: get issuer metadata
    pub fn get_issuer(env: Env, address: Address) -> Option<IssuerRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::IssuerMeta(hash_address(&env, &address)))
    }

    /// Admin: revoke an issuer
    pub fn revoke_issuer(env: Env, issuer: Address) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).expect("not initialized");
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Issuer(hash_address(&env, &issuer)), &false);
        events::emit_issuer_revoked(&env, &issuer, &admin);

        if let Some(mut record) = env
            .storage()
            .persistent()
            .get::<DataKey, IssuerRecord>(&DataKey::IssuerMeta(hash_address(&env, &issuer)))
        {
            record.authorized = false;
            env.storage()
                .persistent()
                .set(&DataKey::IssuerMeta(hash_address(&env, &issuer)), &record);
        }
    }

    /// Issuer: mint a soulbound vaccination NFT
    pub fn mint_vaccination(
        env: Env,
        patient: Address,
        vaccine_name: String,
        date_administered: String,
        issuer: Address,
    ) -> Result<u64, ContractError> {
        mint::mint_vaccination(&env, patient, vaccine_name, date_administered, issuer)
    }

    /// Original issuer or admin: revoke a vaccination record.
    /// The record is marked revoked: true but never deleted (audit trail preserved).
    pub fn revoke_vaccination(env: Env, token_id: u64, revoker: Address) -> Result<(), ContractError> {
        revoker.require_auth();

        let mut record: VaccinationRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .ok_or(ContractError::RecordNotFound)?;

        if record.revoked {
            return Err(ContractError::AlreadyRevoked);
        }

        // Only the original issuer or the current admin may revoke
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)?;

        if revoker != record.issuer && revoker != admin {
            return Err(ContractError::Unauthorized);
        }

        record.revoked = true;
        env.storage().persistent().set(&DataKey::Token(token_id), &record);
        // Also set a dedicated revocation flag for fast lookup
        env.storage().persistent().set(&DataKey::Revoked(token_id), &true);

        events::emit_revoked(&env, token_id, &revoker);

        Ok(())
    }

    /// Transfer is permanently blocked — soulbound enforcement
    pub fn transfer(_env: Env, _from: Address, _to: Address, _token_id: u64) {
        panic!("soulbound: transfers are disabled");
    }

    /// Public: verify vaccination status for a wallet
    pub fn verify_vaccination(env: Env, wallet: Address) -> (bool, Vec<VaccinationRecord>) {
        verify::verify_vaccination(&env, wallet)
    }

    /// Public: batch verify vaccination status for multiple wallets (max 100)
    pub fn batch_verify(env: Env, wallets: Vec<Address>) -> Vec<(Address, bool, Vec<VaccinationRecord>)> {
        verify::batch_verify(&env, wallets)
    }

    /// Check if an address is an authorized issuer
    pub fn is_issuer(env: Env, address: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Issuer(hash_address(&env, &address)))
            .unwrap_or(false)
    }

    /// Public: list currently authorized issuers with pagination.
    pub fn get_all_issuers(env: Env, start: u32, limit: u32) -> Vec<Address> {
        if limit == 0 {
            return Vec::new(&env);
        }

        let issuers: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::IssuerList)
            .unwrap_or(Vec::new(&env));

        let mut active: Vec<Address> = Vec::new(&env);
        for i in 0..issuers.len() {
            let issuer = issuers.get(i).unwrap();
            if Self::is_issuer(env.clone(), issuer.clone()) {
                active.push_back(issuer);
            }
        }

        let mut page: Vec<Address> = Vec::new(&env);
        let mut seen: u32 = 0;
        for i in 0..active.len() {
            if seen < start {
                seen += 1;
                continue;
            }
            if page.len() >= limit {
                break;
            }
            page.push_back(active.get(i).unwrap());
        }
        page
    }

    /// Admin: propose a new admin (two-step transfer). Proposal expires after 24 hours.
    pub fn propose_admin(env: Env, new_admin: Address) -> Result<(), ContractError> {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)?;
        admin.require_auth();
        let expires_at = env.ledger().timestamp() + 86400;
        env.storage().persistent().set(&DataKey::PendingAdmin, &new_admin);
        env.storage().persistent().set(&DataKey::AdminTransferExpiry, &expires_at);
        events::emit_admin_transfer_proposed(&env, &admin, &new_admin, expires_at);
        Ok(())
    }

    /// Proposed admin: accept the admin role.
    pub fn accept_admin(env: Env) -> Result<(), ContractError> {
        let pending: Address = env.storage().persistent().get(&DataKey::PendingAdmin)
            .ok_or(ContractError::NoPendingTransfer)?;
        let expires_at: u64 = env.storage().persistent().get(&DataKey::AdminTransferExpiry)
            .ok_or(ContractError::NoPendingTransfer)?;
        if env.ledger().timestamp() > expires_at {
            return Err(ContractError::ProposalExpired);
        }
        pending.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &pending);
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        env.storage().persistent().remove(&DataKey::AdminTransferExpiry);
        events::emit_admin_transfer_accepted(&env, &pending);
        Ok(())
    }

    /// Admin: upgrade the contract WASM.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), ContractError> {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)?;
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        events::emit_contract_upgraded(&env, &new_wasm_hash, &admin);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env, String};

    #[test]
    fn test_get_all_issuers_empty() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(VacciChainContract, ());
        let client = VacciChainContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let issuers = client.get_all_issuers(&0, &10);
        assert_eq!(issuers.len(), 0);
    }

    #[test]
    fn test_get_all_issuers_single() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(VacciChainContract, ());
        let client = VacciChainContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let issuer = Address::generate(&env);
        client.initialize(&admin);
        client.add_issuer(
            &issuer,
            &String::from_str(&env, "General Hospital"),
            &String::from_str(&env, "LIC-12345"),
            &String::from_str(&env, "USA"),
        );

        let issuers = client.get_all_issuers(&0, &10);
        assert_eq!(issuers.len(), 1);
        assert_eq!(issuers.get(0).unwrap(), issuer);
    }

    #[test]
    fn test_get_all_issuers_multiple_paginated() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(VacciChainContract, ());
        let client = VacciChainContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let issuer1 = Address::generate(&env);
        let issuer2 = Address::generate(&env);
        let issuer3 = Address::generate(&env);
        client.initialize(&admin);
        for issuer in [issuer1.clone(), issuer2.clone(), issuer3.clone()] {
            client.add_issuer(
                &issuer,
                &String::from_str(&env, "General Hospital"),
                &String::from_str(&env, "LIC-12345"),
                &String::from_str(&env, "USA"),
            );
        }

        let page1 = client.get_all_issuers(&0, &2);
        assert_eq!(page1.len(), 2);
        assert_eq!(page1.get(0).unwrap(), issuer1);
        assert_eq!(page1.get(1).unwrap(), issuer2);

        let page2 = client.get_all_issuers(&2, &2);
        assert_eq!(page2.len(), 1);
        assert_eq!(page2.get(0).unwrap(), issuer3);
    }
}
