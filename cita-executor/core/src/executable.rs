use std::fmt;
use std::collections::HashMap;
use std::str::FromStr;

use contracts::Resource;
use cita_types::{Address, H160, U256};
use evm::env_info::EnvInfo;
use types::{
    reserved_addresses,
    transaction::{Action, SignedTransaction}
};

use error::ExecutionError;
use state::{
    backend::Backend as StateBackend,
    State
};

const MSG_INVALID_TX_DATA_SIZE: &'static str = "The length of transaction data is less than four bytes";
const MSG_INVALID_TX_DATA_PARAM: &'static str = "Data should have at least one parameter";

pub type GroupAccounts = HashMap<Address, Vec<Address>>;
pub type AccountPerms = HashMap<Address, Vec<Resource>>;

#[derive(Debug)]
pub enum CheckMode {
    Permission,
    Quota,
    Both,
    Pass,
}

impl CheckMode {
    pub fn new(perm: bool, quota: bool) -> CheckMode {
        match (perm, quota) {
            (true, true) => CheckMode::Both,
            (true, false) => CheckMode::Permission,
            (false, true) => CheckMode::Quota,
            (false, false) => CheckMode::Pass,
        }
    }
}

impl fmt::Display for CheckMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CheckMode::Both => write!(f, "Both permission and quota"),
            CheckMode::Permission => write!(f, "Only permission"),
            CheckMode::Quota => write!(f, "Only quota"),
            CheckMode::Pass => write!(f, "No check"),
        }
    }
}

pub struct Executable<'a> {
    sender: Address,
    tx: &'a SignedTransaction,

    super_admin_account: Option<Address>,
    group_accounts: &'a GroupAccounts,
    account_perms: &'a AccountPerms,

    minimal_gas: U256,
    gas_used: U256,
    gas_limit: U256,
    account_gas_limit: U256,
}

impl<'a> Executable<'a>
{
    pub fn new<B: StateBackend>(
        tx: &'a SignedTransaction,
        state: &'a State<B>,
        info: &'a EnvInfo,
        minimal_gas: U256,
    ) -> Executable<'a> {
        Self {
            sender: *tx.sender(),
            tx,

            super_admin_account: state.super_admin_account,
            group_accounts: &state.group_accounts,
            account_perms: &state.account_permissions,

            minimal_gas,
            gas_used: info.gas_used,
            gas_limit: info.gas_limit,
            account_gas_limit: info.account_gas_limit,
        }
    }

    pub fn checked(self, check_mode: &CheckMode) -> Result<(), ExecutionError> {
        self.check_tx_gas()?;

        match check_mode {
            CheckMode::Permission => self.check_permission()?,
            CheckMode::Quota => self.check_quota()?,
            CheckMode::Both => { self.check_permission()?; self.check_quota()? },
            CheckMode::Pass => (),
        }

        Ok(())
    }

    fn check_permission(&self) -> Result<(), ExecutionError> {
        self.check_tx_sendable()?;

        match self.tx.action {
            Action::Create => self.check_contract_creatable()?,
            Action::Call(address) => self.check_contract_callable(&address)?,
            Action::AmendData => self.check_super_admin()?,
            _ => {}
        }

        Ok(())
    }

    /// Check the quota
    fn check_quota(&self) -> Result<(), ExecutionError> {
        let tx_gas = self.tx.gas;
        let gas_used = self.gas_used;
        let gas_limit = self.gas_limit;
        let account_gas_limit = self.account_gas_limit;

        if self.sender != Address::zero() {
            // validate if transaction fits into given block
            if gas_used + tx_gas > gas_limit {
                Err(ExecutionError::BlockGasLimitReached {
                    gas_limit: gas_limit,
                    gas_used: gas_used,
                    gas: tx_gas,
                })?
            }
            if tx_gas > account_gas_limit {
                Err(ExecutionError::AccountGasLimitReached {
                    gas_limit: account_gas_limit,
                    gas: tx_gas,
                })?
            }
        }

        Ok(())
    }

    fn check_tx_gas(&self) -> Result<(), ExecutionError> {
        if self.sender != Address::zero() && self.tx.gas < self.minimal_gas {
            Err(ExecutionError::NotEnoughBaseGas {required: self.minimal_gas, got: self.tx.gas})?
        }

        Ok(())
    }

    /// Check permission: send transaction
    fn check_tx_sendable(&self) -> Result<(), ExecutionError> {
        let sender = *self.tx.sender();
        let cont = Address::from_str(reserved_addresses::PERMISSION_SEND_TX).unwrap();
        let func = vec![0; 4];
        let has_permission = self.has_resource(&cont, &func[..]);

        trace!("has send tx permission: {:?}", has_permission);

        if sender != Address::zero() && !has_permission {
            Err(ExecutionError::NoTransactionPermission)?
        }

        Ok(())
    }

    fn check_super_admin(&self) -> Result<(), ExecutionError> {
        self.super_admin_account
            .ok_or(ExecutionError::NoTransactionPermission)
            .and_then(|admin| {
                if self.sender != admin {
                    Err(ExecutionError::NoTransactionPermission)
                } else {
                    Ok(())
                }
            })
    }

    fn check_contract_creatable(&self) -> Result<(), ExecutionError> {
        let cont = Address::from_str(reserved_addresses::PERMISSION_CREATE_CONTRACT).unwrap();
        let func = vec![0; 4];
        let has_permission = self.has_resource(&cont, &func[..]);

        trace!("has create contract permission: {:?}", has_permission);

        if self.sender != Address::zero() && !has_permission {
            Err(ExecutionError::NoContractPermission)?
        }

        Ok(())
    }

    /// Check permission: call contract
    fn check_contract_callable(&self, cont: &Address) -> Result<(), ExecutionError> {
        let group_mnt = Address::from_str(reserved_addresses::GROUP_MANAGEMENT).unwrap();
        let tx_data = &self.tx.data;
        trace!("tx.data {:?}", tx_data);

        if tx_data.len() < 4 {
            Err(ExecutionError::TransactionMalformed(String::from(MSG_INVALID_TX_DATA_SIZE)))?
        }
        if *cont == group_mnt {
            if tx_data.len() < 36 {
                Err(ExecutionError::TransactionMalformed(String::from(MSG_INVALID_TX_DATA_PARAM)))?
            }

            // func_sig and param
            self.check_origin_group(&tx_data[0..4], &H160::from(&tx_data[16..36]))?;
        }

        let func = &tx_data[0..4];
        let has_permission = self.has_resource(cont, func);

        trace!("has call contract permission: {:?}", has_permission);

        if !has_permission {
            Err(ExecutionError::NoCallPermission)?
        }

        Ok(())
    }

    /// Check permission with parameter: origin group
    fn check_origin_group(&self, func: &[u8], param: &Address) -> Result<(), ExecutionError> {
        use contracts::permission_management::contains_resource;

        let cont = Address::from_str(reserved_addresses::GROUP_MANAGEMENT).unwrap();
        let has_permission = contains_resource(self.account_perms, &self.sender, cont, func);

        trace!("Sender has call contract permission: {:?}", has_permission);

        if !has_permission && !contains_resource(self.account_perms, param, cont, func) {
            Err(ExecutionError::NoCallPermission)?
        }

        Ok(())
    }

    /// Check the account has resource
    /// 1. Check the account has resource
    /// 2. Check all account's groups has resource
    fn has_resource(&self, contract: &Address, func_sig: &[u8]) -> bool {
        use contracts::permission_management::contains_resource;

        if contains_resource(self.account_perms, &self.sender, *contract, func_sig) {
            return true;
        }

        for group in self.get_sender_groups() {
            if contains_resource(self.account_perms, &group, *contract, func_sig) {
                return true;
            }
        }

        return false;
    }

    /// Get all sender's groups
    fn get_sender_groups(&self) -> Vec<Address> {
        self.group_accounts
            .iter()
            .filter_map(|(group, accounts)| {
                if accounts.contains(&self.sender) {
                    Some(*group)
                } else {
                    None
                }
            })
            .collect::<Vec<Address>>()
    }
}
