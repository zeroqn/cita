pragma solidity ^0.4.14;


/// @title A library for operation of contract
/// @author ["Cryptape Technologies <contact@cryptape.com>"]
/// @notice Use prefix to import it
/// @dev TODO more interface
library ContractCheck {

    /// @notice Check an address is contract address
    /// @param _target The address to be checked
    /// @return true if successed, false otherwise
    function isContract(address _target)
        internal
        constant
        returns (bool)
    {
        uint size;
        assembly { size := extcodesize(_target) }
        return size > 0;
    }
}
