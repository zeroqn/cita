pragma solidity ^0.4.14;


/// @title The enum data of error
/// @author ["Cryptape Technologies <contact@cryptape.com>"]
contract Error {

    enum ErrorType {
        NotAdmin,
        OutOfBaseLimit,
        OutOfBlockLimit,
        NoParentChain,
        NoSideChain,
        NotOneOperate,
        NotClose,
        NotStart,
        NotReady
    }

    event ErrorLog(ErrorType indexed errorType, string message);
}
