// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./SaltKernelFactory.sol";
import "../interfaces/IEntryPoint.sol";
import "solady/auth/Ownable.sol";

contract SaltFactoryStaker is Ownable {
    mapping(SaltKernelFactory => bool) public approved;

    error NotApprovedFactory();

    constructor(address _owner) {
        _initializeOwner(_owner);
    }

    function deployWithFactory(SaltKernelFactory factory, bytes calldata createData, bytes32 salt, bytes calldata signature)
        external
        payable
        returns (address)
    {
        if (!approved[factory]) {
            revert NotApprovedFactory();
        }
        return factory.createAccount(createData, salt, signature);
    }

    function approveFactory(SaltKernelFactory factory, bool approval) external payable onlyOwner {
        approved[factory] = approval;
    }

    function stake(IEntryPoint entryPoint, uint32 unstakeDelay) external payable onlyOwner {
        entryPoint.addStake{value: msg.value}(unstakeDelay);
    }

    function unlockStake(IEntryPoint entryPoint) external payable onlyOwner {
        entryPoint.unlockStake();
    }

    function withdrawStake(IEntryPoint entryPoint, address payable recipient) external payable onlyOwner {
        entryPoint.withdrawStake(recipient);
    }
}
