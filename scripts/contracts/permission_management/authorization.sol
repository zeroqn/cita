pragma solidity ^0.4.14;

import "./permission.sol";
import "../common/address_array.sol";


/// @title Authorization about the permission and account
/// @author ["Cryptape Technologies <contact@cryptape.com>"]
/// @notice The address: 0xffffffffffffffffffffffffffffffffff020006
///         The interface can be called: Only query type
contract Authorization {

    address permissionManagementAddr = 0xffFffFffFFffFFFFFfFfFFfFFFFfffFFff020004;
    address roleManagementAddr = 0xFFFFfFfFFFFFFfFfffFfffffffFffFFffF020007;

    address newPermissionAddr = 0xfFfFffFffffFFfffFfFfFffFFFfFFfFFFf021010;
    address deletePermissionAddr = 0xFFfFfffffFFffFfffFffffffFFfFfFfFfF021011;
    address updatePermissionAddr = 0xfFFfFFfFFFFffffFFFFFfffffFFFFFFFFf021012;
    address setAuthAddr = 0xfFFFffFffFfffFffFfffFfFFfFFFfFffFf021013;
    address cancelAuthAddr = 0xfFFFffFfffFFFFffFfFffffFfFFFfffFfF021014;
    address newRoleAddr = 0xFFFFFfffffFFFfFfffffFfFfffffFFffFf021015;
    address deleteRoleAddr = 0xfFfFFFFFffFFfFFfFFfFFfFfFFfffFFffF021016;
    address updateRoleAddr = 0xFFFFffFFFFfFFFFFFfFFffffFFFFFFFFff021017;
    address setRoleAddr = 0xfFFFfFfFFFFFFffFfFFFFfffFffFfFFFFF021018;
    address cancelRoleAddr = 0xfFFffffffFffFffFFFFFFFFFffFfffFFfF021019;
    address newGroupAddr = 0xFFFFffffffffFFfFffFffFFfFfFfFffFFf02101A;
    address deleteGroupAddr = 0xFFfFfffFffffffffFFfFfFFFFfFFfFfFFF02101B;
    address updateGroupAddr = 0xFFFfFFfffFFffFffffffFFFFFFfFFffffF02101c;
    address sendTxAddr = 0xFFffFFFFfFFFFFFfffFfFFffFfFFFFfFFf021000;
    address createContractAddr = 0xffFFffffFfffFFFfffffFFfFFffFFfFFFf021001;

    address rootGroup = 0xfFFfFFFFFffFFfffFFFFfffffFffffFFfF020009;

    mapping(address => address[]) permissions;
    mapping(address => address[]) accounts;

    address[] all_accounts;

    event AuthSetted(address indexed _account, address indexed _permission);
    event AuthCanceled(address indexed _account, address indexed _permission);
    event AuthCleared(address indexed _account);

    modifier onlyPermissionManagement {
        require(permissionManagementAddr == msg.sender || roleManagementAddr == msg.sender );
        _;
    }

    modifier notSuperAdmin(address _account) {
        require(_account != all_accounts[0]);
        _;
    }

    /// @notice Initialize the superAdmin's auth
    function Authorization(address _superAdmin) public {
        _setAuth(_superAdmin, sendTxAddr);
        _setAuth(_superAdmin, createContractAddr);
        _setAuth(_superAdmin, newPermissionAddr);
        _setAuth(_superAdmin, deletePermissionAddr);
        _setAuth(_superAdmin, updatePermissionAddr);
        _setAuth(_superAdmin, setAuthAddr);
        _setAuth(_superAdmin, cancelAuthAddr);
        _setAuth(_superAdmin, newRoleAddr);
        _setAuth(_superAdmin, deleteRoleAddr);
        _setAuth(_superAdmin, updateRoleAddr);
        _setAuth(_superAdmin, setRoleAddr);
        _setAuth(_superAdmin, cancelRoleAddr);
        _setAuth(_superAdmin, newGroupAddr);
        _setAuth(_superAdmin, deleteGroupAddr);
        _setAuth(_superAdmin, updateGroupAddr);
        // rootGroup: basic permissions
        _setAuth(rootGroup, sendTxAddr);
        _setAuth(rootGroup, createContractAddr);
    }

    /// @notice Set permission to the account
    /// @param _account The account to be setted
    /// @param _permission The permission to be setted
    /// @return true if successed, otherwise false
    function setAuth(address _account, address _permission)
        public
        onlyPermissionManagement
        returns (bool)
    {
        return _setAuth(_account, _permission);
    }

    /// @notice Cancel the account's permission
    /// @param _account The account to be canceled
    /// @param _permission The permission to be canceled
    /// @return true if successed, otherwise false
    function cancelAuth(address _account, address _permission)
        public
        onlyPermissionManagement
        notSuperAdmin(_account)
        returns (bool)
    {
        AddressArray.remove(_account, accounts[_permission]);
        AddressArray.remove(_permission, permissions[_account]);
        AuthCanceled(_account, _permission);
        return true;
    }

    /// @notice Clear the account's permissions
    /// @param _account The account to be cleared
    /// @return true if successed, otherwise false
    function clearAuth(address _account)
        public
        onlyPermissionManagement
        notSuperAdmin(_account)
        returns (bool)
    {
        // Delete the account of all the account's permissions
        for (uint i = 0; i < permissions[_account].length; i++)
            AddressArray.remove(_account, accounts[permissions[_account][i]]);

        delete permissions[_account];
        AddressArray.remove(_account, all_accounts);

        AuthCleared(_account);
        return true;
    }

    /// @notice Clear the auth of the accounts who have the permission
    /// @param _permission The permission to be cleared
    /// @return true if successed, otherwise false
    function clearAuthOfPermission(address _permission)
        public
        onlyPermissionManagement
        returns (bool)
    {
        address[] memory _accounts = queryAccounts(_permission);

        for (uint i = 0; i < _accounts.length; i++)
            assert(cancelAuth(_accounts[i], _permission));

        return true;
    }

    /// @notice Query the account's permissions
    /// @param _account The account to be queried
    /// @return The permissions of account
    function queryPermissions(address _account)
        public
        constant
        returns (address[] _permissions)
    {
        return permissions[_account];
    }

    /// @notice Query the permission's accounts
    /// @param _permission The permission to be queried
    /// @return The accounts of permission
    function queryAccounts(address _permission)
        public
        constant
        returns (address[] _accounts)
    {
        return accounts[_permission];
    }

    /// @notice Query all accounts
    /// @return All the accounts
    function queryAllAccounts()
        public
        constant
        returns (address[])
    {
        return all_accounts;
    }

    /// @notice Check account has a resource
    /// @param _account The account to be checked
    /// @param _cont The contract of resource
    /// @param _func The function signature of resource
    /// @return true if passed, otherwise false
    function checkResource(address _account, address _cont, bytes4 _func)
        public
        constant
        returns (bool)
    {
        address[] memory perms = queryPermissions(_account);

        for (uint i = 0; i < perms.length; i++) {
            Permission perm = Permission(perms[i]);
            if (perm.inPermission(_cont, _func))
                return true;
        }

        return false;
    }

    /// @notice Check account has a permission
    /// @param _account The account to be checked
    /// @param _permission The address of permission
    /// @return true if passed, otherwise false
    function checkPermission(address _account, address _permission)
        public
        constant
        returns (bool)
    {
        return AddressArray.exist(_permission, permissions[_account]);
    }

    /// @notice Private: Set the permission to the account
    function _setAuth(address _account, address _permission)
        private
        returns (bool)
    {
        if (!AddressArray.exist(_permission, permissions[_account]))
            permissions[_account].push(_permission);
        if (!AddressArray.exist(_account, accounts[_permission]))
            accounts[_permission].push(_account);
        if (!AddressArray.exist(_account, all_accounts))
            all_accounts.push(_account);

        AuthSetted(_account, _permission);
        return true;
    }
}
