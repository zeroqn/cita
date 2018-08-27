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

//! Chain manager.

use super::calc_func_sig;
use cita_types::{Address, H160, H256, U256};
use evm::call_type::CallType;
use evm::ext::{Ext, MessageCallResult};
use std::str::FromStr;
use types::reserved_addresses;

const CHAIN_ID: &[u8] = &*b"getChainId()";
const AUTHORITIES: &[u8] = &*b"getAuthorities(uint32)";

lazy_static! {
    static ref CHAIN_ID_HASH: Vec<u8> = calc_func_sig(CHAIN_ID);
    static ref AUTHORITIES_HASH: Vec<u8> = calc_func_sig(AUTHORITIES);
    static ref CONTRACT_ADDRESS: H160 = H160::from_str(reserved_addresses::CHAIN_MANAGER).unwrap();
}

pub struct ChainManagement;

impl ChainManagement {
    pub fn ext_chain_id(ext: &mut Ext, gas: &U256, sender: &Address) -> Option<(U256, u32)> {
        trace!("call system contract ChainManagement.ext_chain_id()");
        let contract = &*CONTRACT_ADDRESS;
        let tx_data = CHAIN_ID_HASH.to_vec();
        let data = &tx_data.as_slice();
        let mut output = Vec::<u8>::new();
        match ext.call(
            gas,
            sender,
            contract,
            None,
            data,
            contract,
            &mut output,
            CallType::Call,
        ) {
            MessageCallResult::Success(gas_left, return_data) => {
                let id = super::to_u256(&return_data).low_u64() as u32;
                Some((gas_left, id))
            }
            MessageCallResult::Reverted(..) | MessageCallResult::Failed => None,
        }
    }

    pub fn ext_authorities(
        ext: &mut Ext,
        gas: &U256,
        sender: &Address,
        chain_id: u32,
    ) -> Option<(U256, Vec<Address>)> {
        trace!(
            "call system contract ChainManagement.ext_authorities({})",
            chain_id
        );
        let contract = &*CONTRACT_ADDRESS;
        let mut tx_data = AUTHORITIES_HASH.to_vec();
        let param = H256::from(u64::from(chain_id));
        tx_data.extend(param.to_vec());
        let data = &tx_data.as_slice();
        let mut output = Vec::<u8>::new();
        match ext.call(
            gas,
            sender,
            contract,
            None,
            data,
            contract,
            &mut output,
            CallType::Call,
        ) {
            MessageCallResult::Success(gas_left, return_data) => {
                trace!(
                    "call system contract ChainManagement.ext_authorities() return [{:?}]",
                    return_data
                );
                let addresses = super::to_address_vec(&return_data);
                Some((gas_left, addresses))
            }
            MessageCallResult::Reverted(..) | MessageCallResult::Failed => None,
        }
    }
}
