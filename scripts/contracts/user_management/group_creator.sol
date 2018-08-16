pragma solidity ^0.4.14;

import "./group.sol";


/// @title Group factory contract to create group contract
/// @author ["Cryptape Technologies <contact@cryptape.com>"]
/// @notice The address: 0xfFFffFfFFFFfFFFfFfffffFFfffffffffF02000B
///         The interface: None
contract GroupCreator {

    address userManagementAddr = 0xFFFffFFfffffFFfffFFffffFFFffFfFffF02000a;

    event GroupCreated(address indexed _id, address indexed _parent, bytes32 indexed _name, address[] accounts);

    /// @notice Create a new group contract
    /// @param _parent The parent group
    /// @param _name  The name of group
    /// @return New group's accounts
    function createGroup(address _parent, bytes32 _name, address[] _accounts)
        public
        returns (Group groupAddress)
    {
        require(userManagementAddr == msg.sender);

        groupAddress = new Group(_parent, _name, _accounts);
        GroupCreated(groupAddress, _parent, _name, _accounts);
    }
}
