// CITA
// Copyright 2016-2018 Cryptape Technologies LLC.

// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any
// later version.

// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! System Config

use std::str::FromStr;

use ethabi::{decode, ParamType, Token};

use cita_types::{Address, H256};
use types::ids::BlockId;
use types::reserved_addresses;

use super::calc_func_sig;
use super::ContractCallExt;
use libexecutor::executor::{EconomicalModel, Executor};
use num::FromPrimitive;

lazy_static! {
    static ref DELAY_BLOCK_NUMBER_HASH: Vec<u8> = calc_func_sig(b"getDelayBlockNumber()");
    static ref PERMISSION_CHECK_HASH: Vec<u8> = calc_func_sig(b"getPermissionCheck()");
    static ref QUOTA_CHECK_HASH: Vec<u8> = calc_func_sig(b"getQuotaCheck()");
    static ref FEE_BACK_PLATFORM_CHECK_HASH: Vec<u8> =
        calc_func_sig(b"getFeeBackPlatformCheck()");
    static ref CHAIN_OWNER_HASH: Vec<u8> = calc_func_sig(b"getChainOwner()");
    static ref CHAIN_NAME_HASH: Vec<u8> = calc_func_sig(b"getChainName()");
    static ref CHAIN_ID_HASH: Vec<u8> = calc_func_sig(b"getChainId()");
    static ref OPERATOR_HASH: Vec<u8> = calc_func_sig(b"getOperator()");
    static ref WEBSITE_HASH: Vec<u8> = calc_func_sig(b"getWebsite()");
    static ref BLOCK_INTERVAL_HASH: Vec<u8> = calc_func_sig(b"getBlockInterval()");
    static ref ECONOMICAL_MODEL_HASH: Vec<u8> = calc_func_sig(b"getEconomicalModel()");
    static ref GET_TOKEN_INFO_HASH: Vec<u8> = calc_func_sig(b"getTokenInfo()");
    static ref CONTRACT_ADDRESS: Address =
        Address::from_str(reserved_addresses::SYS_CONFIG).unwrap();
}

#[derive(PartialEq, Debug)]
pub struct TokenInfo {
    pub name: String,
    pub symbol: String,
    pub avatar: String,
}

/// Configuration items from system contract
pub struct SysConfig<'a> {
    executor: &'a Executor,
}

impl<'a> SysConfig<'a> {
    pub fn new(executor: &'a Executor) -> Self {
        SysConfig { executor }
    }

    fn get_value(
        &self,
        param_types: &[ParamType],
        method: &[u8],
        block_id: Option<BlockId>,
    ) -> Result<Vec<Token>, String> {
        let address = &*CONTRACT_ADDRESS;
        let block_id = block_id.unwrap_or(BlockId::Latest);
        let output = self.executor.call_method(address, method, None, block_id)?;
        trace!("sys_config value output: {:?}", output);
        decode(param_types, &output).map_err(|_| "decode value error".to_string())
    }

    fn get_latest_value(&self, param_types: &[ParamType], method: &[u8]) -> Vec<Token> {
        let address = &*CONTRACT_ADDRESS;
        let output = self.executor.call_method_latest(address, method);
        trace!("sys_config value output: {:?}", output);
        decode(param_types, &output).expect("decode value error")
    }

    /// Delay block number before validate
    pub fn delay_block_number(&self) -> u64 {
        let value = self
            .get_latest_value(&[ParamType::Uint(256)], DELAY_BLOCK_NUMBER_HASH.as_slice())
            .remove(0)
            .to_uint()
            .expect("decode delay number");
        let number = H256::from(value).low_u64();
        debug!("delay block number: {:?}", number);
        number
    }

    /// Whether check permission or not
    pub fn permission_check(&self) -> bool {
        let check = self
            .get_latest_value(&[ParamType::Bool], PERMISSION_CHECK_HASH.as_slice())
            .remove(0)
            .to_bool()
            .expect("decode check permission");
        debug!("check permission: {:?}", check);
        check
    }

    /// Whether check quota or not
    pub fn quota_check(&self) -> bool {
        let check = self
            .get_latest_value(&[ParamType::Bool], QUOTA_CHECK_HASH.as_slice())
            .remove(0)
            .to_bool()
            .expect("decode check quota");
        debug!("check quota: {:?}", check);
        check
    }

    /// Check fee back to platform or node
    pub fn fee_back_platform_check(&self) -> bool {
        let check =
            self.get_value(
                &[ParamType::Bool],
                FEE_BACK_PLATFORM_CHECK_HASH.as_slice(),
                Some(BlockId::Latest),
            ).ok()
                .and_then(|mut x| x.remove(0).to_bool())
                .unwrap_or_else(|| false);
        debug!("check fee back platform: {:?}", check);
        check
    }

    /// The owner of current chain
    pub fn chain_owner(&self) -> Address {
        let chain_owner =
            self.get_value(
                &[ParamType::Address],
                CHAIN_OWNER_HASH.as_slice(),
                Some(BlockId::Latest),
            ).ok()
                .and_then(|mut x| x.remove(0).to_address())
                .unwrap_or_else(|| [0u8; 20]);
        debug!("Get chain owner: {:?}", chain_owner);
        Address::from(chain_owner)
    }

    /// The name of current chain
    pub fn chain_name(&self, block_id: Option<BlockId>) -> Result<String, String> {
        let mut chain_name_bs =
            self.get_value(&[ParamType::String], CHAIN_NAME_HASH.as_slice(), block_id)?;
        chain_name_bs
            .remove(0)
            .to_string()
            .ok_or("decode chain name error".to_string())
    }

    /// The id of current chain
    pub fn chain_id(&self) -> u32 {
        let value = self
            .get_latest_value(&[ParamType::Uint(64)], CHAIN_ID_HASH.as_slice())
            .remove(0)
            .to_uint()
            .expect("decode chain id");
        let chain_id = H256::from(value).low_u64() as u32;
        debug!("current chain id: {:?}", chain_id);
        chain_id
    }

    /// The operator of current chain
    pub fn operator(&self, block_id: Option<BlockId>) -> Result<String, String> {
        let mut operator_bs = self.get_value(&[ParamType::String], OPERATOR_HASH.as_slice(), block_id)?;
        operator_bs
            .remove(0)
            .to_string()
            .ok_or("decode operator error".to_string())
    }

    /// Current operator's website URL
    pub fn website(&self, block_id: Option<BlockId>) -> Result<String, String> {
        let mut website_bs = self.get_value(&[ParamType::String], WEBSITE_HASH.as_slice(), block_id)?;
        website_bs
            .remove(0)
            .to_string()
            .ok_or("decode website error".to_string())
    }

    /// The interval time for creating a block (milliseconds)
    pub fn block_interval(&self) -> u64 {
        let value = self
            .get_latest_value(&[ParamType::Uint(64)], BLOCK_INTERVAL_HASH.as_slice())
            .remove(0)
            .to_uint()
            .expect("decode block interval");
        let interval = H256::from(value).low_u64();
        debug!("block interval: {:?}", interval);
        interval
    }

    /// enum EconomicalModel { Quota, Charge }
    /// Quota: Default config is quota
    /// Charge: Charging by gas * gasPrice and reward for proposer
    pub fn economical_model(&self) -> EconomicalModel {
        let value = self
            .get_latest_value(&[ParamType::Uint(64)], ECONOMICAL_MODEL_HASH.as_slice())
            .remove(0)
            .to_uint()
            .expect("decode economical model");
        let t = H256::from(value).low_u64() as u8;
        debug!("economical model: {:?}", t);
        EconomicalModel::from_u8(t).expect("unknown economical model")
    }

    pub fn token_info(&self) -> TokenInfo {
        let address = &*CONTRACT_ADDRESS;
        let output = self
            .executor
            .call_method_latest(address, GET_TOKEN_INFO_HASH.as_slice());
        let mut token_info = decode(
            &[ParamType::String, ParamType::String, ParamType::String],
            &output,
        ).expect("decode value error");
        TokenInfo {
            name: token_info
                .remove(0)
                .to_string()
                .expect("decode token name error"),
            symbol: token_info
                .remove(0)
                .to_string()
                .expect("decode token symbol error"),
            avatar: token_info
                .remove(0)
                .to_string()
                .expect("decode token avatar error"),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate logger;
    extern crate mktemp;

    use super::{EconomicalModel, SysConfig, TokenInfo};
    use cita_types::Address;
    use std::str::FromStr;
    use tests::helpers::init_executor;

    #[test]
    fn test_delay_block_number() {
        let executor = init_executor(vec![("SysConfig.delayBlockNumber", "2")]);
        let number = SysConfig::new(&executor).delay_block_number();
        assert_eq!(number, 2);
    }

    #[test]
    fn test_permission_check() {
        let executor = init_executor(vec![("SysConfig.checkPermission", "false")]);
        let check_permission = SysConfig::new(&executor).permission_check();
        assert_eq!(check_permission, false);
    }

    #[test]
    fn test_quota_check() {
        let executor = init_executor(vec![("SysConfig.checkQuota", "true")]);
        let check_quota = SysConfig::new(&executor).quota_check();
        assert_eq!(check_quota, true);
    }

    #[test]
    fn test_fee_back_platform_check() {
        let executor = init_executor(vec![("SysConfig.checkFeeBackPlatform", "true")]);
        let check_fee_back_platform = SysConfig::new(&executor).fee_back_platform_check();
        assert_eq!(check_fee_back_platform, true);
    }

    #[test]
    fn test_chain_owner() {
        let executor = init_executor(vec![(
            "SysConfig.chainOwner",
            "0x0000000000000000000000000000000000000000",
        )]);
        let value = SysConfig::new(&executor).chain_owner();
        assert_eq!(
            value,
            Address::from_str("0000000000000000000000000000000000000000").unwrap()
        );
    }

    #[test]
    fn test_chain_name() {
        let executor = init_executor(vec![("SysConfig.chainName", "test-chain")]);
        let value = SysConfig::new(&executor).chain_name(None).unwrap();
        assert_eq!(value, "test-chain");
    }

    #[test]
    fn test_chain_id() {
        let executor = init_executor(vec![("SysConfig.chainId", "123")]);
        let value = SysConfig::new(&executor).chain_id();
        assert_eq!(value, 123);
    }

    #[test]
    fn test_operator() {
        let executor = init_executor(vec![("SysConfig.operator", "test-operator")]);
        let value = SysConfig::new(&executor).operator(None).unwrap();
        assert_eq!(value, "test-operator");
    }

    #[test]
    fn test_website() {
        let executor = init_executor(vec![("SysConfig.website", "https://www.cryptape.com")]);
        let value = SysConfig::new(&executor).website(None).unwrap();
        assert_eq!(value, "https://www.cryptape.com");
    }

    #[test]
    fn test_block_interval() {
        let executor = init_executor(vec![("SysConfig.blockInterval", "3006")]);
        let value = SysConfig::new(&executor).block_interval();
        assert_eq!(value, 3006);
    }

    #[test]
    fn test_economical_model() {
        let executor = init_executor(vec![("SysConfig.economicalModel", "1")]);
        let value = SysConfig::new(&executor).economical_model();
        assert_eq!(value, EconomicalModel::Charge);
    }

    #[test]
    fn test_token_info() {
        let executor = init_executor(vec![
            ("SysConfig.name", "name"),
            ("SysConfig.symbol", "symbol"),
            ("SysConfig.avatar", "avatar"),
        ]);
        let value = SysConfig::new(&executor).token_info();
        assert_eq!(
            value,
            TokenInfo {
                name: "name".to_owned(),
                symbol: "symbol".to_owned(),
                avatar: "avatar".to_owned()
            }
        );
    }
}
