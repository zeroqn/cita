pragma solidity ^0.4.14;


/// @title Permission contract
/// @author ["Cryptape Technologies <contact@cryptape.com>"]
/// @notice The address: Created by permissionCreator
///         The interface can be called: Only query type
contract Permission {

    struct Resource {
        // Contract address
        address cont;
        // Function hash
        bytes4 func;
    }

    address permissionManagementAddr = 0xffFffFffFFffFFFFFfFfFFfFFFFfffFFff020004;
    Resource[] resources;
    bytes32 name;

    event ResourcesAdded(address[] _conts, bytes4[] _funcs);
    event ResourcesDeleted(address[] _conts, bytes4[] _funcs);
    event NameUpdated(bytes32 indexed _oldName, bytes32 indexed _name);

    modifier onlyPermissionManagement {
        require(permissionManagementAddr == msg.sender);
        _;
    }

    /// @notice Constructor
    function Permission(bytes32 _name, address[] _conts, bytes4[] _funcs)
        public
    {
        name = _name;
        require(_addResources(_conts, _funcs));
    }

    /// @notice Add the resources
    /// @param _conts The contracts of resource
    /// @param _funcs The function signature of resource
    /// @return true if successed, otherwise false
    function addResources(address[] _conts, bytes4[] _funcs)
        public
        onlyPermissionManagement
        returns (bool)
    {
        require(_addResources(_conts, _funcs));
        return true;
    }

    /// @notice Delete the resources
    /// @param _conts The contracts of resource
    /// @param _funcs The function signature of resource
    /// @return true if successed, otherwise false
    function deleteResources(address[] _conts, bytes4[] _funcs)
        public
        onlyPermissionManagement
        returns (bool)
    {
        for (uint i = 0; i < _conts.length; i++)
            require(resourceDelete(_conts[i], _funcs[i]));

        ResourcesDeleted(_conts, _funcs);
        return true;
    }

    /// @notice Update permission's name
    /// @param _name The new name
    /// @return true if successed, otherwise false
    function updateName(bytes32 _name)
        public
        onlyPermissionManagement
        returns (bool)
    {
        NameUpdated(name, _name);
        name = _name;
        return true;
    }

    /// @notice Destruct self
    /// @return true if successed, otherwise false
    function close()
        public
        onlyPermissionManagement
        returns (bool)
    {
        selfdestruct(msg.sender);
        return true;
    }

    /// @notice Check resource in the permission
    /// @param cont The contract address of the resource
    /// @param func The function signature of the resource
    /// @return true if in permission, otherwise false
    function inPermission(address cont, bytes4 func)
        public
        constant
        returns (bool)
    {
        for (uint i = 0; i < resources.length; i++) {
            if (cont == resources[i].cont && func == resources[i].func)
                return true;
        }

        return false;
    }

    /// @notice Query the information of the permission
    /// @return The information of permission: name and resources
    function queryInfo()
        public
        constant
        returns (bytes32, address[], bytes4[])
    {
        uint len = resources.length;
        address[] memory conts = new address[](len);
        bytes4[] memory funcs = new bytes4[](len);

        for (uint i = 0; i < resources.length; i++) {
            conts[i] = resources[i].cont;
            funcs[i] = resources[i].func;
        }

        return (name, conts, funcs);
    }

    /// @notice Query the name of the permission
    /// @return The name of permission
    function queryName()
        public
        constant
        returns (bytes32)
    {
        return name;
    }

    /// @notice Query the resource of the permission
    /// @return The resources of permission
    function queryResource()
        public
        constant
        returns (address[], bytes4[])
    {
        uint len = resources.length;
        address[] memory conts = new address[](len);
        bytes4[] memory funcs = new bytes4[](len);

        for (uint i = 0; i < resources.length; i++) {
            conts[i] = resources[i].cont;
            funcs[i] = resources[i].func;
        }

        return (conts, funcs);
    }

    /// @notice Private: Delete the value of the resources
    function resourceDelete(address _cont, bytes4 _func)
        private
        returns (bool)
    {
        uint index = resourceIndex(_cont,  _func);
        // Not found
        if (index >= resources.length)
            return false;

        // Move the last element to the index of array
        resources[index] = resources[resources.length - 1];

        // Also delete the last element
        delete resources[resources.length-1];
        resources.length--;
        return true;
    }

    /// @notice Private: Get the index of the value in the resources
    function resourceIndex(address _cont, bytes4 _func)
        private
        constant
        returns (uint i)
    {
        for (i = 0; i < resources.length; i++) {
            if (_cont == resources[i].cont && _func == resources[i].func)
                return i;
        }
    }

    /// @notice Private: Add resources
    function _addResources(address[] _conts, bytes4[] _funcs)
        private
        returns (bool)
    {
        for (uint i = 0; i < _conts.length; i++) {
            if (!inResources(_conts[i], _funcs[i])) {
                Resource memory res = Resource(_conts[i], _funcs[i]);
                resources.push(res);
            }
        }

        ResourcesAdded(_conts, _funcs);
        return true;
    }

    /// @notice Private: Check the duplicate resource
    function inResources(address _cont, bytes4 _func)
        private
        constant
        returns (bool)
    {
        for (uint i = 0; i < resources.length; i++) {
            if (_cont == resources[i].cont && _func == resources[i].func)
                return true;
        }

        return false;
    }
}
