pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import {Kernel} from "../src/Kernel.sol";
import {KernelFactory} from "../src/factory/KernelFactory.sol";
import {SaltKernelFactory} from "../src/factory/SaltKernelFactory.sol";
import {SaltFactoryStaker} from "../src/factory/SaltFactoryStaker.sol";
import {ECDSAValidator} from "../src/validator/ECDSAValidator.sol";
import {EntryPointLib} from "../src/sdk/TestBase/erc4337Util.sol";
import {IEntryPoint} from "../src/interfaces/IEntryPoint.sol";
import {IHook} from "../src/interfaces/IERC7579Modules.sol";
import {ValidatorLib} from "../src/utils/ValidationTypeLib.sol";
import {ValidationId} from "../src/types/Types.sol";
import {Ownable} from "solady/auth/Ownable.sol";

contract SaltKernelFactoryTest is Test {
    bytes32 private constant _CREATE_ACCOUNT_TYPEHASH = keccak256("CreateAccount(bytes32 dataHash,bytes32 salt)");

    IEntryPoint entrypoint;
    Kernel impl;
    SaltKernelFactory factory;
    ECDSAValidator validator;

    address ownerAddr;
    address deployerAddr;
    uint256 deployerKey;

    function setUp() public {
        entrypoint = IEntryPoint(EntryPointLib.deploy());
        impl = new Kernel(entrypoint);
        ownerAddr = makeAddr("Owner");
        (deployerAddr, deployerKey) = makeAddrAndKey("Deployer");
        factory = new SaltKernelFactory(address(impl), ownerAddr, deployerAddr);
        validator = new ECDSAValidator();
    }

    function _initData(address user) internal view returns (bytes memory) {
        bytes[] memory initConfig = new bytes[](0);
        return abi.encodeWithSelector(
            Kernel.initialize.selector,
            ValidatorLib.validatorToIdentifier(validator),
            IHook(address(0)),
            abi.encodePacked(user),
            hex"",
            initConfig
        );
    }

    function _sign(bytes32 salt, bytes memory data, uint256 key) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(_CREATE_ACCOUNT_TYPEHASH, keccak256(data), salt));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", factory.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function testAddressOnlyDependsOnSalt() external {
        bytes32 salt = bytes32(uint256(0xa11ce));
        address predicted = factory.getAddress(salt);

        (address userA,) = makeAddrAndKey("A");

        bytes memory data = _initData(userA);
        bytes memory sig = _sign(salt, data, deployerKey);
        address deployed = factory.createAccount(data, salt, sig);
        assertEq(deployed, predicted);
    }

    function testDifferentSaltDifferentAddress() external {
        (address user,) = makeAddrAndKey("User");
        bytes memory data = _initData(user);

        bytes32 saltA = bytes32(uint256(1));
        bytes32 saltB = bytes32(uint256(2));

        address a = factory.createAccount(data, saltA, _sign(saltA, data, deployerKey));
        address b = factory.createAccount(data, saltB, _sign(saltB, data, deployerKey));
        assertTrue(a != b);
    }

    function testInitDataAppliedOnDeploy() external {
        (address user,) = makeAddrAndKey("User");
        bytes32 salt = bytes32(uint256(0xbeef));
        bytes memory data = _initData(user);

        Kernel kernel = Kernel(payable(factory.createAccount(data, salt, _sign(salt, data, deployerKey))));

        assertEq(
            ValidationId.unwrap(kernel.rootValidator()),
            ValidationId.unwrap(ValidatorLib.validatorToIdentifier(validator))
        );
        assertEq(kernel.currentNonce(), 1);
    }

    function testReDeployIsNoop() external {
        (address userA,) = makeAddrAndKey("A");
        (address userB,) = makeAddrAndKey("B");
        bytes32 salt = bytes32(uint256(0xc0ffee));
        bytes memory dataA = _initData(userA);
        bytes memory dataB = _initData(userB);

        address first = factory.createAccount(dataA, salt, _sign(salt, dataA, deployerKey));
        // Re-deploy at the same salt with a separate signature for the new data:
        // proxy is already deployed → no-op, returns the same address.
        address second = factory.createAccount(dataB, salt, _sign(salt, dataB, deployerKey));
        assertEq(first, second);
    }

    function testSetDeployerRejectsZero() external {
        vm.prank(ownerAddr);
        vm.expectRevert(SaltKernelFactory.DeployerNotSet.selector);
        factory.setDeployer(address(0));
    }

    function testConstructorRejectsZeroOwner() external {
        vm.expectRevert(SaltKernelFactory.OwnerNotSet.selector);
        new SaltKernelFactory(address(impl), address(0), deployerAddr);
    }

    function testConstructorRejectsZeroDeployer() external {
        vm.expectRevert(SaltKernelFactory.DeployerNotSet.selector);
        new SaltKernelFactory(address(impl), ownerAddr, address(0));
    }

    function testRevertsWithBadSignature() external {
        (, uint256 attackerKey) = makeAddrAndKey("Attacker");
        (address user,) = makeAddrAndKey("User");
        bytes32 salt = bytes32(uint256(8));
        bytes memory data = _initData(user);
        bytes memory badSig = _sign(salt, data, attackerKey);

        vm.expectRevert(SaltKernelFactory.NotDeployer.selector);
        factory.createAccount(data, salt, badSig);
    }

    function testOnlyOwnerCanSetDeployer() external {
        address rando = makeAddr("Rando");
        vm.prank(rando);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.setDeployer(rando);

        address newDeployer = makeAddr("NewDeployer");
        vm.prank(ownerAddr);
        factory.setDeployer(newDeployer);
        assertEq(factory.deployer(), newDeployer);
    }

    function testSignatureCannotBeReplayedAcrossSalt() external {
        (address user,) = makeAddrAndKey("User");
        bytes memory data = _initData(user);
        bytes32 saltA = bytes32(uint256(0xaaaa));
        bytes32 saltB = bytes32(uint256(0xbbbb));

        bytes memory sigForA = _sign(saltA, data, deployerKey);

        // valid for saltA
        factory.createAccount(data, saltA, sigForA);

        // same sig must NOT authorize a different salt
        vm.expectRevert(SaltKernelFactory.NotDeployer.selector);
        factory.createAccount(data, saltB, sigForA);
    }

    function testSignatureCannotBeReplayedAcrossData() external {
        // Mempool front-run scenario: attacker grabs a (sig, salt, data) tx, swaps `data`
        // for their own init payload, and rebroadcasts. With dataHash bound into the digest,
        // the substituted call must revert NotDeployer.
        (address victim,) = makeAddrAndKey("Victim");
        (address attacker,) = makeAddrAndKey("Attacker");
        bytes32 salt = bytes32(uint256(0xfeed));

        bytes memory victimData = _initData(victim);
        bytes memory attackerData = _initData(attacker);
        bytes memory victimSig = _sign(salt, victimData, deployerKey);

        vm.expectRevert(SaltKernelFactory.NotDeployer.selector);
        factory.createAccount(attackerData, salt, victimSig);
    }

    function testStakerDeployForwardsSignature() external {
        address stakerOwner = makeAddr("StakerOwner");
        SaltFactoryStaker staker = new SaltFactoryStaker(stakerOwner);
        vm.prank(stakerOwner);
        staker.approveFactory(factory, true);

        (address user,) = makeAddrAndKey("User");
        bytes32 salt = bytes32(uint256(0xd00d));
        bytes memory data = _initData(user);
        bytes memory sig = _sign(salt, data, deployerKey);

        address predicted = factory.getAddress(salt);
        address deployed = staker.deployWithFactory(factory, data, salt, sig);
        assertEq(predicted, deployed);
    }

    function testStakerRejectsUnapprovedFactory() external {
        address stakerOwner = makeAddr("StakerOwner");
        SaltFactoryStaker staker = new SaltFactoryStaker(stakerOwner);

        (address user,) = makeAddrAndKey("User");
        bytes32 salt = bytes32(uint256(0xfeed));
        bytes memory data = _initData(user);
        bytes memory sig = _sign(salt, data, deployerKey);

        vm.expectRevert(SaltFactoryStaker.NotApprovedFactory.selector);
        staker.deployWithFactory(factory, data, salt, sig);
    }

    function testStakerForwardsBadSignatureRevert() external {
        address stakerOwner = makeAddr("StakerOwner");
        SaltFactoryStaker staker = new SaltFactoryStaker(stakerOwner);
        vm.prank(stakerOwner);
        staker.approveFactory(factory, true);

        (, uint256 attackerKey) = makeAddrAndKey("Attacker");
        (address user,) = makeAddrAndKey("User");
        bytes32 salt = bytes32(uint256(0xbad));
        bytes memory data = _initData(user);
        bytes memory badSig = _sign(salt, data, attackerKey);

        vm.expectRevert(SaltKernelFactory.NotDeployer.selector);
        staker.deployWithFactory(factory, data, salt, badSig);
    }
}
