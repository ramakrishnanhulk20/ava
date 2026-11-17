// Does not cover real ML-DSA-87 maths or the real precompiles: mocks stand in for both here. The live proof (npm run prove:m1) covers them.
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";
import {IQorePQC, PqcProbe} from "../src/PqcProbe.sol";

enum Answer {
    Normal,
    Empty,
    Short,
    Reverts,
    NotABool
}

/// Stands in for pqcKeyStatus at 0x...0a02. Etched, so all of its state is set through calls.
contract MockPqcStatus {
    struct Key {
        bool registered;
        uint8 algorithmId;
        bytes pubkey;
        bool possessionProven;
    }

    Answer public answer;
    mapping(address => Key) internal keys;

    function setAnswer(Answer a) external {
        answer = a;
    }

    function setKey(address account, bool registered, uint8 algorithmId, bytes calldata pubkey, bool proven) external {
        keys[account] = Key(registered, algorithmId, pubkey, proven);
    }

    function pqcKeyStatus(address account) external view returns (bool, uint8, bytes memory, bool) {
        Answer a = answer;
        if (a == Answer.Empty) {
            assembly {
                return(0, 0)
            }
        }
        if (a == Answer.Short) {
            // The four head words with no length word for the key.
            assembly {
                mstore(0, 1)
                mstore(32, 1)
                mstore(64, 0x80)
                mstore(96, 1)
                return(0, 128)
            }
        }
        if (a == Answer.Reverts) revert("status down");
        Key storage k = keys[account];
        return (k.registered, k.algorithmId, k.pubkey, k.possessionProven);
    }
}

/// Stands in for pqcVerify at 0x...0a01. It accepts only the exact (key, signature, message)
/// triples a test registers, the way a real verifier accepts only what was really signed.
contract MockPqcVerify {
    Answer public answer;
    mapping(bytes32 => bool) internal accepted;

    function setAnswer(Answer a) external {
        answer = a;
    }

    function accept(bytes calldata pubkey, bytes calldata signature, bytes calldata message) external {
        accepted[keccak256(abi.encode(pubkey, signature, message))] = true;
    }

    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool)
    {
        Answer a = answer;
        if (a == Answer.Empty) {
            assembly {
                return(0, 0)
            }
        }
        if (a == Answer.Short) {
            assembly {
                mstore(0, 1)
                return(0, 31)
            }
        }
        if (a == Answer.NotABool) {
            assembly {
                mstore(0, 2)
                return(0, 32)
            }
        }
        if (a == Answer.Reverts) revert("verify down");
        return accepted[keccak256(abi.encode(pubkey, signature, message))];
    }
}

contract PqcProbeTest is Test {
    address internal constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
    address internal constant PQC_STATUS = 0x0000000000000000000000000000000000000a02;

    event Recorded(address indexed signer, bytes32 indexed digest, uint256 nonce);

    PqcProbe internal probe;
    MockPqcStatus internal status = MockPqcStatus(PQC_STATUS);
    MockPqcVerify internal verifier = MockPqcVerify(PQC_VERIFY);

    address internal signer = makeAddr("signer");
    bytes32 internal digest = keccak256("board minutes, 16 Nov");
    bytes internal pubkey;
    bytes internal sig;

    function setUp() public {
        vm.etch(PQC_STATUS, type(MockPqcStatus).runtimeCode);
        vm.etch(PQC_VERIFY, type(MockPqcVerify).runtimeCode);
        probe = new PqcProbe();
        pubkey = filled(2592, 0x11);
        sig = filled(4627, 0x22);
        status.setKey(signer, true, 1, pubkey, true);
    }

    function filled(uint256 length, bytes1 fill) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i; i < length; ++i) {
            out[i] = fill;
        }
    }

    function acceptCurrent() internal returns (bytes memory message) {
        message = probe.messageFor(signer, digest);
        verifier.accept(pubkey, sig, message);
    }

    function expectBadSignature() internal {
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.BadSignature.selector, signer));
    }

    function test_ValidSignatureEmitsRecordedAndBumpsNonce() public {
        acceptCurrent();
        vm.expectEmit(true, true, false, true, address(probe));
        emit Recorded(signer, digest, 0);
        probe.record(signer, digest, sig);
        assertEq(probe.nonces(signer), 1);
    }

    function test_AnySenderCanSubmitAValidSignature() public {
        acceptCurrent();
        vm.prank(makeAddr("relayer"));
        probe.record(signer, digest, sig);
        assertEq(probe.nonces(signer), 1);
    }

    function test_SenderBeingTheSignerGrantsNothing() public {
        vm.prank(signer);
        expectBadSignature();
        probe.record(signer, digest, sig);
        assertEq(probe.nonces(signer), 0);
    }

    function test_ReplayRevertsBecauseTheNonceMoved() public {
        bytes memory first = acceptCurrent();
        probe.record(signer, digest, sig);

        bytes memory next = probe.messageFor(signer, digest);
        assertNotEq(keccak256(next), keccak256(first));
        vm.expectCall(PQC_VERIFY, abi.encodeCall(IQorePQC.pqcVerify, (pubkey, sig, next)));
        expectBadSignature();
        probe.record(signer, digest, sig);
        assertEq(probe.nonces(signer), 1);
    }

    function test_RevertsWhenSignerHasNoKey() public {
        address stranger = makeAddr("stranger");
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.NoPqcKey.selector, stranger));
        probe.record(stranger, digest, sig);
    }

    function test_RevertsForTheZeroSigner() public {
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.NoPqcKey.selector, address(0)));
        probe.record(address(0), digest, sig);
    }

    function testFuzz_RevertsWhenAlgorithmIsNotMlDsa87(uint8 algorithmId) public {
        vm.assume(algorithmId != 1);
        status.setKey(signer, true, algorithmId, pubkey, true);
        acceptCurrent();
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.WrongAlgorithm.selector, signer, algorithmId));
        probe.record(signer, digest, sig);
    }

    function test_RevertsWhenPossessionIsNotProven() public {
        status.setKey(signer, true, 1, pubkey, false);
        acceptCurrent();
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PossessionNotProven.selector, signer));
        probe.record(signer, digest, sig);
    }

    function testFuzz_RevertsWhenKeyIsNot2592Bytes(uint16 length) public {
        vm.assume(length != 2592);
        bytes memory key = filled(length, 0x11);
        status.setKey(signer, true, 1, key, true);
        verifier.accept(key, sig, probe.messageFor(signer, digest));
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.BadKeyLength.selector, signer, uint256(length)));
        probe.record(signer, digest, sig);
    }

    function test_RevertsWhenVerifyReturnsFalse() public {
        expectBadSignature();
        probe.record(signer, digest, sig);
        assertEq(probe.nonces(signer), 0);
    }

    function test_RevertsWhenSignatureIsNot4627BytesEvenIfTheVerifierWouldAccept() public {
        bytes memory short = filled(4626, 0x22);
        verifier.accept(pubkey, short, probe.messageFor(signer, digest));
        expectBadSignature();
        probe.record(signer, digest, short);
    }

    function test_RevertsOnEmptyDataFromKeyStatus() public {
        status.setAnswer(Answer.Empty);
        acceptCurrent();
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PrecompileUnavailable.selector, PQC_STATUS));
        probe.record(signer, digest, sig);
    }

    function test_RevertsOnEmptyDataFromVerify() public {
        acceptCurrent();
        verifier.setAnswer(Answer.Empty);
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PrecompileUnavailable.selector, PQC_VERIFY));
        probe.record(signer, digest, sig);
    }

    function test_RevertsWhenKeyStatusHasNoCode() public {
        vm.etch(PQC_STATUS, "");
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PrecompileUnavailable.selector, PQC_STATUS));
        probe.record(signer, digest, sig);
    }

    function test_RevertsWhenVerifyHasNoCode() public {
        vm.etch(PQC_VERIFY, "");
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PrecompileUnavailable.selector, PQC_VERIFY));
        probe.record(signer, digest, sig);
    }

    function test_RevertsOnShortDataFromKeyStatus() public {
        status.setAnswer(Answer.Short);
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PrecompileUnavailable.selector, PQC_STATUS));
        probe.record(signer, digest, sig);
    }

    function test_RevertsOnShortDataFromVerify() public {
        acceptCurrent();
        verifier.setAnswer(Answer.Short);
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PrecompileUnavailable.selector, PQC_VERIFY));
        probe.record(signer, digest, sig);
    }

    function test_RevertsWhenKeyStatusReverts() public {
        status.setAnswer(Answer.Reverts);
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PrecompileUnavailable.selector, PQC_STATUS));
        probe.record(signer, digest, sig);
    }

    function test_RevertsWhenVerifyReverts() public {
        acceptCurrent();
        verifier.setAnswer(Answer.Reverts);
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PrecompileUnavailable.selector, PQC_VERIFY));
        probe.record(signer, digest, sig);
    }

    function test_RevertsWhenVerifyAnswerIsNotABool() public {
        acceptCurrent();
        verifier.setAnswer(Answer.NotABool);
        vm.expectRevert(abi.encodeWithSelector(PqcProbe.PrecompileUnavailable.selector, PQC_VERIFY));
        probe.record(signer, digest, sig);
    }

    function test_MessageIsTheSpecifiedEncoding() public view {
        bytes memory message = probe.messageFor(signer, digest);
        assertEq(message.length, 192);
        assertEq(
            message,
            abi.encode(keccak256("ava.probe.v1"), block.chainid, address(probe), signer, digest, uint256(0))
        );
    }

    function testFuzz_MessageIsTheSpecifiedEncoding(address who, bytes32 what, uint64 chainId) public {
        vm.chainId(chainId);
        assertEq(
            probe.messageFor(who, what),
            abi.encode(keccak256("ava.probe.v1"), uint256(chainId), address(probe), who, what, uint256(0))
        );
    }

    function test_MessageChangesWithChainId() public {
        bytes memory before = probe.messageFor(signer, digest);
        vm.chainId(block.chainid + 1);
        assertNotEq(keccak256(probe.messageFor(signer, digest)), keccak256(before));
    }

    function test_MessageChangesWithContractAddress() public {
        PqcProbe other = new PqcProbe();
        assertNotEq(keccak256(other.messageFor(signer, digest)), keccak256(probe.messageFor(signer, digest)));
    }

    function test_MessageChangesWithSigner() public {
        assertNotEq(
            keccak256(probe.messageFor(makeAddr("other signer"), digest)), keccak256(probe.messageFor(signer, digest))
        );
    }

    function test_MessageChangesWithDigest() public view {
        assertNotEq(
            keccak256(probe.messageFor(signer, bytes32(uint256(digest) ^ 1))),
            keccak256(probe.messageFor(signer, digest))
        );
    }

    function test_MessageChangesWithNonce() public {
        bytes memory before = acceptCurrent();
        probe.record(signer, digest, sig);
        assertNotEq(keccak256(probe.messageFor(signer, digest)), keccak256(before));
    }

    function test_MessageNeverStartsWithQ() public view {
        assertNotEq(bytes("ava.probe.v1")[0], bytes1("q"));
        assertNotEq(probe.messageFor(signer, digest)[0], bytes1("q"));
    }

    function testFuzz_NonceIsStrictlySequential(uint8 rounds) public {
        uint256 n = bound(rounds, 1, 12);
        for (uint256 i; i < n; ++i) {
            assertEq(probe.nonces(signer), i);
            acceptCurrent();
            vm.expectEmit(true, true, false, true, address(probe));
            emit Recorded(signer, digest, i);
            probe.record(signer, digest, sig);
        }
        assertEq(probe.nonces(signer), n);
    }

    function test_RefusesValue() public {
        vm.deal(address(this), 1 ether);
        (bool plain,) = address(probe).call{value: 1}("");
        assertFalse(plain);

        acceptCurrent();
        (bool withRecord,) =
            address(probe).call{value: 1}(abi.encodeCall(PqcProbe.record, (signer, digest, sig)));
        assertFalse(withRecord);
        assertEq(address(probe).balance, 0);
        assertEq(probe.nonces(signer), 0);
    }
}
