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

//! Permission management.

use super::ContractCallExt;
use super::{calc_func_sig, to_address_vec, to_resource_vec};
use cita_types::{Address, H160, H256};
use libexecutor::executor::Executor;
use std::collections::HashMap;
use std::str::FromStr;
use types::reserved_addresses;

const ALLACCOUNTS: &[u8] = &*b"queryAllAccounts()";
const PERMISSIONS: &[u8] = &*b"queryPermissions(address)";
const RESOURCES: &[u8] = &*b"queryResource()";

lazy_static! {
    static ref ALLACCOUNTS_HASH: Vec<u8> = calc_func_sig(ALLACCOUNTS);
    static ref PERMISSIONS_HASH: Vec<u8> = calc_func_sig(PERMISSIONS);
    static ref RESOURCES_HASH: Vec<u8> = calc_func_sig(RESOURCES);
    static ref CONTRACT_ADDRESS: H160 = H160::from_str(reserved_addresses::AUTHORIZATION).unwrap();
}

#[derive(PartialEq, Clone, Default, Debug, Serialize, Deserialize, Eq, PartialOrd, Ord)]
pub struct Resource {
    pub cont: Address,
    pub func: Vec<u8>,
}

impl Resource {
    pub fn new(cont: Address, func: Vec<u8>) -> Self {
        Resource { cont, func }
    }

    pub fn set_cont(&mut self, addr: Address) {
        self.cont = addr;
    }

    pub fn get_cont(&self) -> Address {
        self.cont
    }

    pub fn set_func(&mut self, func: Vec<u8>) {
        self.func = func;
    }

    pub fn get_func(&self) -> &Vec<u8> {
        &self.func
    }
}

pub struct PermissionManagement;

impl PermissionManagement {
    pub fn load_account_permissions(executor: &Executor) -> HashMap<Address, Vec<Resource>> {
        let mut account_permissions = HashMap::new();
        let accounts = PermissionManagement::all_accounts(executor);

        trace!("ALl accounts: {:?}", accounts);
        for account in accounts {
            let permissions = PermissionManagement::permissions(executor, &(H256::from(account)));
            let mut resources = vec![];
            for permission in permissions {
                resources.extend(PermissionManagement::resources(executor, &permission));
            }
            account_permissions.insert(account, resources);
        }

        account_permissions
    }

    /// Account array
    pub fn all_accounts(executor: &Executor) -> Vec<Address> {
        let output = executor.call_method_latest(&*CONTRACT_ADDRESS, &*ALLACCOUNTS_HASH.as_slice());
        trace!("All accounts output: {:?}", output);

        to_address_vec(&output)
    }

    pub fn get_super_admin_account(executor: &Executor) -> Option<Address> {
        let accounts = PermissionManagement::all_accounts(executor);
        if accounts.is_empty() {
            None
        } else {
            Some(accounts[0])
        }
    }

    /// Permission array
    pub fn permissions(executor: &Executor, param: &H256) -> Vec<Address> {
        let mut tx_data = PERMISSIONS_HASH.to_vec();
        tx_data.extend(param.to_vec());
        debug!("tx_data: {:?}", tx_data);
        let output = executor.call_method_latest(&*CONTRACT_ADDRESS, &tx_data.as_slice());
        debug!("Permissions output: {:?}", output);

        to_address_vec(&output)
    }

    /// Resources array
    pub fn resources(executor: &Executor, address: &Address) -> Vec<Resource> {
        let output = executor.call_method_latest(address, &*RESOURCES_HASH.as_slice());
        trace!("Resources output: {:?}", output);

        to_resource_vec(&output)
    }
}

/// Check the account contains the resource
pub fn contains_resource(
    account_permissions: &HashMap<Address, Vec<Resource>>,
    account: &Address,
    cont: Address,
    func: &[u8],
) -> bool {
    match account_permissions.get(account) {
        Some(resources) => {
            let resource = Resource {
                cont,
                func: func.to_owned(),
            };
            resources.iter().any(|res| *res == resource)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {

    extern crate logger;
    extern crate mktemp;

    use super::contains_resource;
    use super::{calc_func_sig, PermissionManagement, Resource};
    use cita_types::{Address, H160, H256};
    use std::collections::HashMap;
    use std::str::FromStr;
    use tests::helpers::init_executor;
    use types::reserved_addresses;

    const NEW_PERMISSION: &[u8] = &*b"newPermission(bytes32,address[],bytes4[])";
    const DELETE_PERMISSION: &[u8] = &*b"deletePermission(address)";
    const ADD_RESOURCES: &[u8] = &*b"addResources(address,address[],bytes4[])";
    const DELETE_RESOURCES: &[u8] = &*b"deleteResources(address,address[],bytes4[])";
    const UPDATE_PERMISSIONNAME: &[u8] = &*b"updatePermissionName(address,bytes32)";
    const SET_AUTHORIZATION: &[u8] = &*b"setAuthorization(address,address)";
    const SET_AUTHORIZATIONS: &[u8] = &*b"setAuthorizations(address,address[])";
    const CANCEL_AUTHORIZATION: &[u8] = &*b"cancelAuthorization(address,address)";
    const CLEAR_AUTHORIZATION: &[u8] = &*b"clearAuthorization(address)";
    const CANCEL_AUTHORIZATIONS: &[u8] = &*b"cancelAuthorizations(address,address[])";
    const NEW_ROLE: &[u8] = &*b"newRole(bytes32,address[])";
    const DELETE_ROLE: &[u8] = &*b"deleteRole(address)";
    const ADD_PERMISSIONS: &[u8] = &*b"addPermissions(address,address[])";
    const DELETE_PERMISSIONS: &[u8] = &*b"deletePermissions(address,address[])";
    const UPDATE_ROLENAME: &[u8] = &*b"updateRoleName(address,bytes32)";
    const SET_ROLE: &[u8] = &*b"setRole(address,address)";
    const CANCEL_ROLE: &[u8] = &*b"cancelRole(address,address)";
    const CLEAR_ROLE: &[u8] = &*b"clearRole(address)";
    const NEW_GROUP: &[u8] = &*b"newGroup(address,bytes32,address[])";
    const DELETE_GROUP: &[u8] = &*b"deleteGroup(address,address)";
    const ADD_ACCOUNTS: &[u8] = &*b"addAccounts(address,address,address[])";
    const DELETE_ACCOUNTS: &[u8] = &*b"deleteAccounts(address,address,address[])";
    const UPDATE_GROUPNAME: &[u8] = &*b"updateGroupName(address,address,bytes32)";
    const APPROVE_NODE: &[u8] = &*b"approveNode(address)";
    const DELETE_NODE: &[u8] = &*b"deleteNode(address)";
    const SET_STAKE: &[u8] = &*b"setStake(address,uint64)";
    const SET_DEFAULTAQL: &[u8] = &*b"setDefaultAQL(uint256)";
    const SET_AQL: &[u8] = &*b"setAQL(address,uint256)";
    const SET_BQL: &[u8] = &*b"setBQL(uint256)";

    #[test]
    fn test_contains_resource() {
        let mut permission_resources: HashMap<Address, Vec<Resource>> = HashMap::new();
        let addr1 = Address::from(0x111);
        let addr2 = Address::from(0x222);
        let mut func = calc_func_sig(ADD_RESOURCES);
        let resources = vec![
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: func.clone(),
            },
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_CREATOR).unwrap(),
                func: func.clone(),
            },
        ];
        permission_resources.insert(addr1, resources);
        assert!(contains_resource(
            &permission_resources,
            &addr1,
            Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
            &func
        ));
        assert!(contains_resource(
            &permission_resources,
            &addr1,
            Address::from_str(reserved_addresses::PERMISSION_CREATOR).unwrap(),
            &func
        ));
        assert!(!contains_resource(
            &permission_resources,
            &addr2,
            Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
            &func
        ));
        assert!(!contains_resource(
            &permission_resources,
            &addr1,
            Address::from_str(reserved_addresses::AUTHORIZATION).unwrap(),
            &func
        ));
        func[3] += 1;
        assert!(!contains_resource(
            &permission_resources,
            &addr1,
            Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
            &func
        ));
    }

    #[test]
    fn test_all_accounts() {
        let executor = init_executor(vec![(
            "Authorization.superAdmin",
            "0x4b5ae4567ad5d9fb92bc9afd6a657e6fa1300000",
        )]);
        let all_accounts: Vec<Address> = PermissionManagement::all_accounts(&executor);

        assert_eq!(
            all_accounts,
            vec![
                Address::from_str("4b5ae4567ad5d9fb92bc9afd6a657e6fa1300000").unwrap(),
                Address::from_str(reserved_addresses::GROUP).unwrap(),
            ]
        );
    }

    #[test]
    fn test_permissions() {
        let executor = init_executor(vec![
            ((
                "Authorization.superAdmin",
                "0x4b5ae4567ad5d9fb92bc9afd6a657e6fa1300000",
            )),
        ]);
        let super_admin = Address::from_str("4b5ae4567ad5d9fb92bc9afd6a657e6fa1300000").unwrap();
        let mut permissions: Vec<Address> =
            PermissionManagement::permissions(&executor, &(H256::from(super_admin)));
        permissions.sort();

        let mut expected_permissions = vec![
            Address::from_str(reserved_addresses::PERMISSION_NEW_PERMISSION).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_DELETE_PERMISSION).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_UPDATE_PERMISSION).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_SET_AUTH).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_CANCEL_AUTH).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_NEW_ROLE).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_DELETE_ROLE).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_UPDATE_ROLE).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_SET_ROLE).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_CANCEL_ROLE).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_NEW_GROUP).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_DELETE_GROUP).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_UPDATE_GROUP).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_SEND_TX).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_CREATE_CONTRACT).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_NEW_NODE).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_DELETE_NODE).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_UPDATE_NODE).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_ACCOUNT_QUOTA).unwrap(),
            Address::from_str(reserved_addresses::PERMISSION_BLOCK_QUOTA).unwrap(),
        ];
        expected_permissions.sort();

        assert_eq!(permissions, expected_permissions);
    }

    #[test]
    fn test_resources() {
        let executor = init_executor(vec![]);
        let permission = Address::from_str(reserved_addresses::PERMISSION_NEW_PERMISSION).unwrap();
        let resources: Vec<Resource> = PermissionManagement::resources(&executor, &permission);
        assert_eq!(
            resources,
            vec![Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(NEW_PERMISSION),
            }]
        );
    }

    #[test]
    fn test_resources_from_not_exist_permission() {
        let executor = init_executor(vec![]);
        let permission = Address::from(0x13);
        let resources: Vec<Resource> = PermissionManagement::resources(&executor, &permission);
        assert_eq!(resources, vec![]);
    }

    #[test]
    fn test_load_account_permissions() {
        let executor = init_executor(vec![(
            "Authorization.superAdmin",
            "0x4b5ae4567ad5d9fb92bc9afd6a657e6fa1300000",
        )]);
        let super_admin = Address::from_str("4b5ae4567ad5d9fb92bc9afd6a657e6fa1300000").unwrap();
        let account_permissions: HashMap<Address, Vec<Resource>> =
            PermissionManagement::load_account_permissions(&executor);
        assert_eq!(account_permissions.contains_key(&super_admin), true);

        let mut resources = (*account_permissions.get(&super_admin).unwrap()).clone();
        resources.sort();

        let mut expected_resources = vec![
            // newPermission
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(NEW_PERMISSION),
            },
            // deletePermission
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(DELETE_PERMISSION),
            },
            // updatePermission
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(ADD_RESOURCES),
            },
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(DELETE_RESOURCES),
            },
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(UPDATE_PERMISSIONNAME),
            },
            // setAuth
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(SET_AUTHORIZATION),
            },
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(SET_AUTHORIZATIONS),
            },
            // cancelAuth
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(CANCEL_AUTHORIZATION),
            },
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(CLEAR_AUTHORIZATION),
            },
            Resource {
                cont: Address::from_str(reserved_addresses::PERMISSION_MANAGEMENT).unwrap(),
                func: calc_func_sig(CANCEL_AUTHORIZATIONS),
            },
            // newRole
            Resource {
                cont: H160::from_str(reserved_addresses::ROLE_MANAGEMENT).unwrap(),
                func: calc_func_sig(NEW_ROLE),
            },
            // deleteRole
            Resource {
                cont: H160::from_str(reserved_addresses::ROLE_MANAGEMENT).unwrap(),
                func: calc_func_sig(DELETE_ROLE),
            },
            // updateRole
            Resource {
                cont: H160::from_str(reserved_addresses::ROLE_MANAGEMENT).unwrap(),
                func: calc_func_sig(ADD_PERMISSIONS),
            },
            Resource {
                cont: H160::from_str(reserved_addresses::ROLE_MANAGEMENT).unwrap(),
                func: calc_func_sig(DELETE_PERMISSIONS),
            },
            Resource {
                cont: H160::from_str(reserved_addresses::ROLE_MANAGEMENT).unwrap(),
                func: calc_func_sig(UPDATE_ROLENAME),
            },
            // setRole
            Resource {
                cont: H160::from_str(reserved_addresses::ROLE_MANAGEMENT).unwrap(),
                func: calc_func_sig(SET_ROLE),
            },
            // cancelRole
            Resource {
                cont: H160::from_str(reserved_addresses::ROLE_MANAGEMENT).unwrap(),
                func: calc_func_sig(CANCEL_ROLE),
            },
            Resource {
                cont: H160::from_str(reserved_addresses::ROLE_MANAGEMENT).unwrap(),
                func: calc_func_sig(CLEAR_ROLE),
            },
            // newGroup
            Resource {
                cont: H160::from_str(reserved_addresses::GROUP_MANAGEMENT).unwrap(),
                func: calc_func_sig(NEW_GROUP),
            },
            // deleteGroup
            Resource {
                cont: H160::from_str(reserved_addresses::GROUP_MANAGEMENT).unwrap(),
                func: calc_func_sig(DELETE_GROUP),
            },
            // updateGroup
            Resource {
                cont: H160::from_str(reserved_addresses::GROUP_MANAGEMENT).unwrap(),
                func: calc_func_sig(ADD_ACCOUNTS),
            },
            Resource {
                cont: H160::from_str(reserved_addresses::GROUP_MANAGEMENT).unwrap(),
                func: calc_func_sig(DELETE_ACCOUNTS),
            },
            Resource {
                cont: H160::from_str(reserved_addresses::GROUP_MANAGEMENT).unwrap(),
                func: calc_func_sig(UPDATE_GROUPNAME),
            },
            // senTx
            Resource {
                cont: H160::from_str(reserved_addresses::PERMISSION_SEND_TX).unwrap(),
                func: vec![0, 0, 0, 0],
            },
            // createContract
            Resource {
                cont: H160::from_str(reserved_addresses::PERMISSION_CREATE_CONTRACT).unwrap(),
                func: vec![0, 0, 0, 0],
            },
            // new node
            Resource {
                cont: H160::from_str(reserved_addresses::NODE_MANAGER).unwrap(),
                func: calc_func_sig(APPROVE_NODE),
            },
            // delete node
            Resource {
                cont: H160::from_str(reserved_addresses::NODE_MANAGER).unwrap(),
                func: calc_func_sig(DELETE_NODE),
            },
            // update node
            Resource {
                cont: H160::from_str(reserved_addresses::NODE_MANAGER).unwrap(),
                func: calc_func_sig(SET_STAKE),
            },
            // accountQuota
            Resource {
                cont: H160::from_str(reserved_addresses::QUOTA_MANAGER).unwrap(),
                func: calc_func_sig(SET_DEFAULTAQL),
            },
            Resource {
                cont: H160::from_str(reserved_addresses::QUOTA_MANAGER).unwrap(),
                func: calc_func_sig(SET_AQL),
            },
            // blockQuota
            Resource {
                cont: H160::from_str(reserved_addresses::QUOTA_MANAGER).unwrap(),
                func: calc_func_sig(SET_BQL),
            },
        ];
        expected_resources.sort();

        assert_eq!(resources, expected_resources);
    }
}
