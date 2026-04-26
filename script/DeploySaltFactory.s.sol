pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import "src/Kernel.sol";
import "src/factory/SaltKernelFactory.sol";
import "src/factory/SaltFactoryStaker.sol";
import "src/validator/ECDSAValidator.sol";
import "src/interfaces/IEntryPoint.sol";
import "src/interfaces/IStakeManager.sol";
import "src/interfaces/IERC7579Modules.sol";
import {ValidatorLib} from "src/utils/ValidationTypeLib.sol";

contract DeploySaltFactory is Script {
    address constant KERNEL_IMPL = 0xBAC849bB641841b44E965fB01A4Bf5F074f84b4D; // v3.1
    address constant ECDSA_VALIDATOR = 0x845ADb2C711129d4f3966735eD98a9F09fC4cE57; // v3.1
    address constant ENTRYPOINT_0_7_ADDR = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    uint256 constant STAKE_AMOUNT = 0.00125 ether;
    uint32 constant UNSTAKE_DELAY = 86400; // 1 day

    bytes32 constant _CREATE_ACCOUNT_TYPEHASH = keccak256("CreateAccount(bytes32 dataHash,bytes32 salt)");

    function run() external {
        // Single key drives broadcaster, staker/factory owner, factory `deployer`,
        // and the EIP-712 signer for the smoke-test deploy.
        uint256 signerPk = vm.envUint("SALT_FACTORY_SIGNER_PK");
        address signer = vm.addr(signerPk);
        console.log("Signer/Owner      :", signer);

        // ── 1. Deploy staker and factory (idempotent: reuse if already deployed) ──
        bytes32 deploySalt = bytes32(0);
        address stakerAddr = vm.computeCreate2Address(
            deploySalt,
            keccak256(abi.encodePacked(type(SaltFactoryStaker).creationCode, abi.encode(signer))),
            signer
        );
        address factoryAddr = vm.computeCreate2Address(
            deploySalt,
            keccak256(
                abi.encodePacked(type(SaltKernelFactory).creationCode, abi.encode(KERNEL_IMPL, signer, signer))
            ),
            signer
        );

        vm.startBroadcast(signerPk);

        SaltFactoryStaker staker = new SaltFactoryStaker{salt: deploySalt}(signer);
        console.log("SaltFactoryStaker :", address(staker), "(deployed)");

        SaltKernelFactory factory = new SaltKernelFactory{salt: deploySalt}(KERNEL_IMPL, signer, signer);
        console.log("SaltKernelFactory :", address(factory), "(deployed)");

        ECDSAValidator validator = ECDSAValidator(ECDSA_VALIDATOR);

        // ── 2. Stake on EntryPoint via staker (top up to STAKE_AMOUNT) ──
        IEntryPoint ep = IEntryPoint(ENTRYPOINT_0_7_ADDR);
        IStakeManager.DepositInfo memory info = ep.getDepositInfo(address(staker));
        if (info.stake < STAKE_AMOUNT) {
            uint256 topUp = STAKE_AMOUNT - info.stake;
            staker.stake{value: topUp}(ep, UNSTAKE_DELAY);
            console.log("Staked (wei)      :", topUp);
        }

        // ── 3. Approve the factory in the staker ──
        if (!staker.approved(factory)) {
            staker.approveFactory(factory, true);
            console.log("Approved factory in staker");
        }

        vm.stopBroadcast();

        // ── 4. Smoke-test: deploy one Kernel account through the staker ──
        bytes32 salt = keccak256("salt-factory-smoke-test");
        bytes memory data = _initData(validator, signer);
        bytes memory sig = _signSalt(factory, signerPk, salt, data);

        address predicted = factory.getAddress(salt);
        console.log("Predicted account :", predicted);

        vm.startBroadcast(signerPk);
        address account = staker.deployWithFactory(factory, data, salt, sig);
        vm.stopBroadcast();

        console.log("Deployed account  :", account);
        require(account == predicted, "address mismatch");
    }

    function _initData(ECDSAValidator validator, address owner) internal pure returns (bytes memory) {
        bytes[] memory initConfig = new bytes[](0);
        return abi.encodeWithSelector(
            Kernel.initialize.selector,
            ValidatorLib.validatorToIdentifier(validator),
            IHook(address(0)),
            abi.encodePacked(owner),
            hex"",
            initConfig
        );
    }

    function _signSalt(SaltKernelFactory factory, uint256 signerPk, bytes32 salt, bytes memory data)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(_CREATE_ACCOUNT_TYPEHASH, keccak256(data), salt));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", factory.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }
}
