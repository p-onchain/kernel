// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {LibClone} from "solady/utils/LibClone.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {KernelFactory} from "./KernelFactory.sol";

/// @title SaltKernelFactory
/// @notice Salt-only deterministic Kernel factory gated by an owner-managed deployer signature.
///         Account address depends only on `salt`; `createAccount` requires an EIP-712 signature
///         from `deployer` over `(salt, data)` so untrusted callers cannot deploy or front-run
///         with substituted init data.
contract SaltKernelFactory is Ownable, EIP712 {
    error NotDeployer();
    error DeployerNotSet();
    error OwnerNotSet();
    error InitializeError();

    bytes32 private constant _CREATE_ACCOUNT_TYPEHASH = keccak256("CreateAccount(bytes32 dataHash,bytes32 salt)");

    address public immutable implementation;

    address public deployer;

    event DeployerChanged(address indexed previousDeployer, address indexed newDeployer);

    constructor(address _impl, address _owner, address _deployer){
        if (_impl == address(0)) revert InitializeError();
        implementation = _impl;

        if (_owner == address(0)) revert OwnerNotSet();
        _initializeOwner(_owner);

        if (_deployer == address(0)) revert DeployerNotSet();
        deployer = _deployer;
    }

    function setDeployer(address newDeployer) external onlyOwner {
        if (newDeployer == address(0)) revert DeployerNotSet();
        emit DeployerChanged(deployer, newDeployer);
        deployer = newDeployer;
    }

    function createAccount(bytes calldata data, bytes32 salt, bytes calldata signature)
        external
        payable
        returns (address)
    {
        bytes32 digest = _hashTypedData(keccak256(abi.encode(_CREATE_ACCOUNT_TYPEHASH, keccak256(data), salt)));
        if (ECDSA.tryRecoverCalldata(digest, signature) != deployer) revert NotDeployer();

        (bool alreadyDeployed, address account) =
            LibClone.createDeterministicERC1967(msg.value, implementation, salt);
        if (!alreadyDeployed) {
            (bool success,) = account.call(data);
            if (!success) {
                revert InitializeError();
            }
        }
        return account;
    }

    function getAddress(bytes32 salt) external view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(implementation, salt, address(this));
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "SaltKernelFactory";
        version = "1.0.0";
    }
}
