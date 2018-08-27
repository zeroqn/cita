// CITA
// Copyright 2016-2017 Cryptape Technologies LLC.

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

//! System contracts.

pub mod chain_manager;
pub mod node_manager;
pub mod permission_management;
pub mod quota_manager;
pub mod sys_config;
pub mod user_management;

pub use self::chain_manager::ChainManagement;
pub use self::node_manager::NodeManager;
pub use self::permission_management::{PermissionManagement, Resource};
pub use self::quota_manager::{AccountGasLimit, QuotaManager};
pub use self::sys_config::SysConfig;
pub use self::user_management::UserManagement;

use cita_types::{Address, H256, U256};
use ethabi::{decode, ParamType, Token};
use libexecutor::call_request::CallRequest;
use libexecutor::executor::Executor;
use types::ids::BlockId;
use util::{sha3, Bytes};

/// Extend `Executor` with some methods related to contract
trait ContractCallExt {
    /// Call a contract method
    fn call_method(
        &self,
        address: &Address,
        encoded_method: &[u8],
        from: Option<Address>,
        block_id: BlockId,
    ) -> Result<Bytes, String>;
    /// Call a contract method on latest block
    fn call_method_on_latest(&self, address: &Address, encoded_method: &[u8]) -> Vec<u8> {
        self.call_method(address, encoded_method, None, BlockId::Latest)
            .unwrap()
    }
}

impl ContractCallExt for Executor {
    fn call_method(
        &self,
        address: &Address,
        encoded_method: &[u8],
        from: Option<Address>,
        block_id: BlockId,
    ) -> Result<Bytes, String> {
        let call_request = CallRequest {
            from,
            to: *address,
            data: Some(encoded_method.to_vec()),
        };

        trace!("data: {:?}", call_request.data);
        self.eth_call(call_request, block_id)
    }
}

// Should move to project top-level for code reuse.
pub fn calc_func_sig(method_name: &[u8]) -> Vec<u8> {
    sha3::keccak256(method_name)[0..4].to_vec()
}

/// Parse solidity return data `address[]` to rust `Vec<Address>`
pub fn to_address_vec(output: &[u8]) -> Vec<Address> {
    match decode(&[ParamType::Array(Box::new(ParamType::Address))], &output) {
        Ok(mut decoded) => {
            let addresses: Vec<Token> = decoded.remove(0).to_array().unwrap();
            let addresses: Vec<Address> = addresses
                .into_iter()
                .map(|de| Address::from(de.to_address().expect("decode address")))
                .collect();
            debug!("Decoded addresses: {:?}", addresses);
            addresses
        }
        Err(_) => Vec::new(),
    }
}

/// Parse solidity return data `uint256[]` to rust `Vec<u64>`
pub fn to_u256_vec(output: &[u8]) -> Vec<U256> {
    let mut decoded = decode(&[ParamType::Array(Box::new(ParamType::Uint(256)))], &output).unwrap();
    let results = decoded.remove(0).to_array().unwrap();
    results
        .into_iter()
        .map(|result| {
            let result = result.to_uint();
            let h256 = H256::from(result.expect("decode u256"));
            U256::from(&h256)
        })
        .collect()
}

/// Parse solidity return data `uint256` to rust `u64`
pub fn to_u256(output: &[u8]) -> U256 {
    let mut decoded = decode(&[ParamType::Uint(256)], &output).expect("decode quota");
    let result = decoded.remove(0).to_uint();

    let h256 = H256::from(result.expect("decode u256"));
    U256::from(&h256)
}

/// Parse solidity return data `Address[], bytes4[]` to rust `Vec<Resource>`
fn to_resource_vec(output: &[u8]) -> Vec<Resource> {
    // Decode the address[] and bytes4[]
    match decode(
        &[
            ParamType::Array(Box::new(ParamType::Address)),
            ParamType::Array(Box::new(ParamType::FixedBytes(4))),
        ],
        &output,
    ) {
        Ok(mut decoded) => {
            trace!("Resource decode: {:?}", decoded);
            let cont_mapiter = decoded
                .remove(0)
                .to_array()
                .unwrap()
                .into_iter()
                .map(|de| Address::from(de.to_address().expect("decode address")));

            let func_mapiter = decoded
                .remove(0)
                .to_array()
                .unwrap()
                .into_iter()
                .map(|func| func.to_fixed_bytes().expect("decode fixed bytes"));

            cont_mapiter
                .zip(func_mapiter)
                .map(|(cont, func)| Resource::new(cont, func))
                .collect()
        }
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn calc_func_sig() {
        let testdata = vec![
            ("thisIsAMethodName(uint256)", vec![0xa8, 0x67, 0x12, 0xe7]),
            ("aMethodNameAgain(bool)", vec![0xa1, 0xbe, 0xa0, 0xac]),
            (
                "thisIsAlsoAMethodName(bytes32)",
                vec![0xb7, 0x7b, 0xc4, 0x01],
            ),
            ("thisIsAMethodNameToo(bytes)", vec![0x87, 0x46, 0x79, 0xca]),
        ];
        for (data, expected) in testdata.into_iter() {
            assert_eq!(super::calc_func_sig(data.as_ref()), expected);
        }
    }
}
