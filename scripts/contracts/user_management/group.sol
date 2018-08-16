pragma solidity ^0.4.14;

import "../common/address_array.sol";


/// @title Group contract
/// @author ["Cryptape Technologies <contact@cryptape.com>"]
/// @notice The address: Created by permissionCreator
///         The interface can be called: Only query type
contract Group {

    address userManagementAddr = 0xFFFffFFfffffFFfffFFffffFFFffFfFffF02000a;

    bytes32 name;
    address parent;
    address[] accounts;
    address[] children;

    event GroupNewed(address indexed _parent, bytes32 indexed _name, address[] _accounts);
    event AccountsAdded(address[] _accounts);
    event AccountsDeleted(address[] _accounts);
    event NameUpdated(bytes32 indexed _oldName, bytes32 indexed _newName);
    event ChildDeleted(address indexed _child);
    event ChildAdded(address indexed _child);

    modifier onlyUserManagement {
        require(userManagementAddr == msg.sender);
        _;
    }

    /// @notice Constructor
    function Group(address _parent, bytes32 _name, address[] _accounts)
        public
    {
        parent = _parent;
        name = _name;
        accounts = _accounts;
        GroupNewed(_parent, _name, _accounts);
    }

    /// @notice Add accounts
    /// @param _accounts The accounts to be added
    /// @return True if successed, otherwise false
    function addAccounts(address[] _accounts)
        public
        onlyUserManagement
        returns (bool)
    {
        for (uint i = 0; i<_accounts.length; i++) {
            if (!AddressArray.exist(_accounts[i], accounts))
                accounts.push(_accounts[i]);
        }

        AccountsAdded(_accounts);
        return true;
    }

    /// @notice Delete accounts
    /// @param _accounts The accounts to be deleted
    /// @return True if successed, otherwise false
    function deleteAccounts(address[] _accounts)
        public
        onlyUserManagement
        returns (bool)
    {
        require(_accounts.length < accounts.length);

        for (uint i = 0; i < _accounts.length; i++)
            assert(AddressArray.remove(_accounts[i], accounts));

        AccountsDeleted(_accounts);
        return true;
    }

    /// @notice Update group name
    /// @param _name  The new name to be updated
    /// @return True if successed, otherwise false
    function updateName(bytes32 _name)
        public
        onlyUserManagement
        returns (bool)
    {
        NameUpdated(name, _name);
        name = _name;
        return true;
    }

    /// @notice Delete a child group
    /// @param _child The child group to be deleted
    /// @return True if successed, otherwise false
    function deleteChild(address _child)
        public
        onlyUserManagement
        returns (bool)
    {
        assert(AddressArray.remove(_child, children));
        ChildDeleted(_child);
        return true;
    }

    /// @notice Add a child group
    /// @param _child The child group to be added
    /// @return True if successed, otherwise false
    function addChild(address _child)
        public
        onlyUserManagement
        returns (bool)
    {
        if (!AddressArray.exist(_child, children))
            children.push(_child);

        ChildAdded(_child);
        return true;
    }

    /// @notice Destruct self
    /// @return True if successed, otherwise false
    function close()
        public
        onlyUserManagement
        returns (bool)
    {
        selfdestruct(msg.sender);
        return true;
    }

    /// @notice Query the information of the group
    /// @dev TODO Include the children group
    /// @return Name and accounts of group
    function queryInfo()
        public
        constant
        returns (bytes32, address[])
    {
        return (name, accounts);
    }

    /// @notice Query the name of the group
    /// @return The name of group
    function queryName()
        public
        constant
        returns (bytes32)
    {
        return name;
    }

    /// @notice Query the accounts of the group
    /// @return The accounts of group
    function queryAccounts()
        public
        constant
        returns (address[])
    {
        return accounts;
    }

    /// @notice Query the child of the group
    /// @dev TODO Rename queryChildren
    /// @return The children of group
    function queryChild()
        public
        constant
        returns (address[])
    {
        return children;
    }

    /// @notice Query the length of children of the group
    /// @return The number of the children group
    function queryChildLength()
        public
        constant
        returns (uint)
    {
        return children.length;
    }

    /// @notice Query the parent of the group
    /// @return The parent of the group
    function queryParent()
        public
        constant
        returns (address)
    {
        return parent;
    }

    /// @notice Check the account in the group
    /// @return Ture if the account in the group, otherwise false
    function inGroup(address _account)
        public
        constant
        returns (bool)
    {
        return AddressArray.exist(_account, accounts);
    }
}
