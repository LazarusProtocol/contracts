#![no_std]

pub mod contract;
pub mod types;

#[cfg(test)]
mod test;

pub use crate::contract::{LazarusVault, LazarusVaultClient};
pub use crate::types::*;
