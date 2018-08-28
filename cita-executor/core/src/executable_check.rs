use contracts::solc::Resource;
use cita_types::{Address, H160, U256};
use evm::env_info::EnvInfo;
use types::{
    reserved_addresses,
    transaction::{Action, SignedTransaction}
};
use util::Bytes;

use std::collections::HashMap;
use std::str::FromStr;

use error::ExecutionError;
use executive::TransactOptions;
use state::{
    backend::Backend as StateBackend,
    State
};

const MSG_INVALID_TX_DATA_SIZE: &'static str = "The length of transaction data is less than four bytes";
const MSG_INVALID_TX_DATA_PARAM: &'static str = "Data should have at least one parameter";

pub type GroupAccounts = HashMap<Address, Vec<Address>>;
pub type AccountPerms = HashMap<Address, Vec<Resource>>;

bitflags! {
    #[derive(Default)]
    pub struct CheckFlags: u32 {
        const CALL = 1 << 0;
        const QUOTA = 1 << 1;
        const SEND_TX = 1 << 2;
        const CREATE_CONTRACT = 1 << 3;
    }
}

impl CheckFlags {
    pub fn from_transact_opts(tx_opts: &TransactOptions) -> Self {
        let mut check_flags = CheckFlags::default();

        check_flags.set(CheckFlags::CALL, tx_opts.check_permission);
        check_flags.set(CheckFlags::QUOTA, tx_opts.check_quota);
        check_flags.set(CheckFlags::SEND_TX, tx_opts.check_send_tx_permission);
        check_flags.set(CheckFlags::CREATE_CONTRACT, tx_opts.check_create_contract_permission);

        check_flags
    }
}

pub trait ExecutableCheck {
    fn check_flags(&self) -> &CheckFlags;

    fn checked(&self, tx: &SignedTransaction) -> Result<(), ExecutionError>;
}

/// Check whether there's enough quota available
pub struct QuotaCheck {
    gas_used: U256,
    gas_limit: U256,
    account_gas_limit: U256,

    check_flags: CheckFlags,
}

impl ExecutableCheck for QuotaCheck {
    fn check_flags(&self) -> &CheckFlags {
        &self.check_flags
    }

    fn checked(&self, tx: &SignedTransaction) -> Result<(), ExecutionError> {
        if !self.check_flags.contains(CheckFlags::QUOTA) {
            return Ok(());
        }

        let sender = *tx.sender();
        let tx_gas = tx.gas;
        let gas_used = self.gas_used;
        let gas_limit = self.gas_limit;
        let account_gas_limit = self.account_gas_limit;

        if sender != Address::zero() {
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
}

impl QuotaCheck {
    pub fn new(info: &EnvInfo, check_flags: CheckFlags) -> QuotaCheck {
        QuotaCheck {
            gas_used: info.gas_used,
            gas_limit: info.gas_limit,
            account_gas_limit: info.account_gas_limit,

            check_flags,
        }
    }
}


pub struct PermCheck<'a> {
    group_accounts: &'a GroupAccounts,
    account_perms:  &'a AccountPerms,

    super_admin_account: Option<Address>,

    check_flags: CheckFlags,
}

impl<'a> ExecutableCheck for PermCheck<'a> {
    fn check_flags(&self) -> &CheckFlags {
        &self.check_flags
    }

    fn checked(&self, tx: &SignedTransaction) -> Result<(), ExecutionError> {
        self.do_permission_check(tx)?;

        Ok(())
    }
}

impl<'a> PermCheck<'a> {
    pub fn new<B: StateBackend>(state: &'a State<B>, check_flags: CheckFlags) -> PermCheck<'a> {
        PermCheck {
            group_accounts: &state.group_accounts,
            account_perms: &state.account_permissions,

            super_admin_account: state.super_admin_account,

            check_flags,
        }
    }

    // Check whether sender has permissions to forward its transaction
    fn do_permission_check(&self, tx: &SignedTransaction) -> Result<(), ExecutionError> {
        if self.check_flags.contains(CheckFlags::SEND_TX) {
            self.check_tx_sendable(tx.sender())?;
        }

        match tx.action {
            Action::Create if self.check_flags.contains(CheckFlags::CREATE_CONTRACT)
                => self.check_contract_creatable(tx.sender())?,
            Action::Call(address) if self.check_flags.contains(CheckFlags::CALL)
                => self.check_contract_callable(tx.sender(), &tx.data, &address)?,
            Action::AmendData => self.is_super_admin(tx.sender())?,
            _ => {}
        }

        Ok(())
    }

    // Check whether sender can send a transaction
    fn check_tx_sendable(&self, sender: &Address) -> Result<(), ExecutionError> {
        let cont = Address::from_str(reserved_addresses::PERMISSION_SEND_TX).unwrap();
        let func = vec![0; 4];
        let has_permission = self.has_resource(sender, &cont, &func[..]);

        trace!("has send tx permission: {:?}", has_permission);

        if *sender != Address::zero() && !has_permission {
            Err(ExecutionError::NoTransactionPermission)?
        }

        Ok(())
    }

    // Check whether sender can create contract
    fn check_contract_creatable(&self, sender: &Address) -> Result<(), ExecutionError> {
        let cont = Address::from_str(reserved_addresses::PERMISSION_CREATE_CONTRACT).unwrap();
        let func = vec![0; 4];
        let has_permission = self.has_resource(sender, &cont, &func[..]);

        trace!("has create contract permission: {:?}", has_permission);

        if *sender != Address::zero() && !has_permission {
            Err(ExecutionError::NoContractPermission)?
        }

        Ok(())
    }

    // Check whether sender can call on given contract
    fn check_contract_callable(&self, sender: &Address, tx_data: &Bytes, cont: &Address) -> Result<(), ExecutionError> {
        let group_mnt = Address::from_str(reserved_addresses::GROUP_MANAGEMENT).unwrap();
        trace!("tx.data {:?}", tx_data);

        if tx_data.is_empty() {
            // Transfer transaction, not function call
            return Ok(());
        }

        if tx_data.len() < 4 {
            Err(ExecutionError::TransactionMalformed(String::from(MSG_INVALID_TX_DATA_SIZE)))?
        }
        if *cont == group_mnt {
            if tx_data.len() < 36 {
                Err(ExecutionError::TransactionMalformed(String::from(MSG_INVALID_TX_DATA_PARAM)))?
            }

            // func_sig and param
            self.check_origin_group(sender, &tx_data[0..4], &H160::from(&tx_data[16..36]))?;
        }

        let func = &tx_data[0..4];
        let has_permission = self.has_resource(sender, cont, func);

        trace!("has call contract permission: {:?}", has_permission);

        if !has_permission {
            Err(ExecutionError::NoCallPermission)?
        }

        Ok(())
    }

    // Check whether sender or origin group(param) has given resource
    fn check_origin_group(&self, sender: &Address, func: &[u8], param: &Address) -> Result<(), ExecutionError> {
        use contracts::solc::permission_management::contains_resource;

        let cont = Address::from_str(reserved_addresses::GROUP_MANAGEMENT).unwrap();
        let has_permission = contains_resource(self.account_perms, sender, cont, func);

        trace!("Sender has call contract permission: {:?}", has_permission);

        if !has_permission && !contains_resource(self.account_perms, param, cont, func) {
            Err(ExecutionError::NoCallPermission)?
        }

        Ok(())
    }

    // Check whether sender has super admin permission
    fn is_super_admin(&self, sender: &Address) -> Result<(), ExecutionError> {
        self.super_admin_account
            .ok_or(ExecutionError::NoTransactionPermission)
            .and_then(|admin| {
                if *sender != admin {
                    Err(ExecutionError::NoTransactionPermission)
                } else {
                    Ok(())
                }
            })
    }

    // Check whether or not sender has given resource
    // 1. if sender has the resource
    // 2. if all sender's groups has the resource
    fn has_resource(&self, sender: &Address, contract: &Address, func_sig: &[u8]) -> bool {
        use contracts::solc::permission_management::contains_resource;

        if contains_resource(self.account_perms, sender, *contract, func_sig) {
            return true;
        }

        for group in self.get_sender_groups(sender) {
            if contains_resource(self.account_perms, &group, *contract, func_sig) {
                return true;
            }
        }

        return false;
    }

    // Get all sender's groups
    fn get_sender_groups(&self, sender: &Address) -> Vec<Address> {
        self.group_accounts
            .iter()
            .filter_map(|(group, accounts)| {
                if accounts.contains(sender) {
                    Some(*group)
                } else {
                    None
                }
            })
            .collect::<Vec<Address>>()
    }
}
