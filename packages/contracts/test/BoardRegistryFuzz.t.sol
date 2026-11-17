// Does not cover: real ML-DSA-87 maths (MarkerVerifyMock models it; BoardRegistryRealSig.t.sol uses real signatures), long random sequences of actions (test/invariant/BoardRegistryInvariant.t.sol), events, or precompile outages (BoardRegistry.t.sol checks both).
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {BoardRegistry} from "../src/BoardRegistry.sol";
import {IQorePQC} from "../src/interfaces/IQorePQC.sol";
import {PqcTestKit} from "./helpers/PqcTestKit.sol";

/// Properties of the signed message, the deadline window, the size caps, the signature length and
/// the nonce order, each over at least 1,000 random inputs. Threat model C1, C2, C5, C8 and C17.
contract BoardRegistryFuzzTest is PqcTestKit {
    // Copied from docs/spec/actions.md so the tests never trust the contract's own constants.
    bytes32 internal constant SPEC_TAG = 0x202301722596364529594a8773ff4f11aeb962e112437e042aa0166a90966a17;
    uint8 internal constant CREATE = 1;
    uint8 internal constant ADD = 2;
    uint8 internal constant REMOVE = 3;
    uint8 internal constant ROTATE = 4;
    uint8 internal constant POST = 5;
    uint8 internal constant TRANSFER = 6;
    uint8 internal constant SEAL_CURRENT = 0;
    uint8 internal constant ROTATE_MODE = 1;
    uint32 internal constant MAX_ENVELOPE_SIZE = 110_000;
    uint64 internal constant MAX_CIPHER_SIZE = 26_214_400;
    uint256 internal constant HOUR = 3600;
    // vm.chainId refuses ids above this, so that an EIP-155 v value still fits in 64 bits.
    uint256 internal constant MAX_CHAIN_ID = type(uint64).max / 2 - 36;

    uint64 internal constant T0 = 1_794_787_200;
    uint32 internal constant ENVELOPE_SIZE = 4_985;
    uint64 internal constant CIPHER_SIZE = 40_000;

    // Every field any write takes, as in BoardRegistry.t.sol: `account` is the chair for CREATE, the
    // member for ADD and REMOVE and the new chair for TRANSFER; `hashA` is the envelope hash, or the
    // docRef for POST; `epoch` is epochAfter, or the document's epoch for POST.
    struct Call {
        uint8 action;
        uint256 boardId;
        address account;
        uint8 mode;
        bytes32 hashA;
        bytes32 hashB;
        uint32 envelopeSize;
        uint64 cipherSize;
        uint64 epoch;
        uint64 deadline;
        bytes32 boardRef;
    }

    BoardRegistry internal registry;
    BoardRegistry internal otherRegistry;

    address internal chair = makeAddr("chair");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal dave = makeAddr("dave");
    address internal erin = makeAddr("erin");

    // chair, bob and carol at epoch 0 with nonce 2. dave and erin hold keys and are not on it.
    uint256 internal board;

    function setUp() public {
        vm.warp(T0);
        _etchMarkerPqcMocks();
        registry = new BoardRegistry();
        otherRegistry = new BoardRegistry();
        _registerKey(chair, _keyOf(chair));
        _registerKey(bob, _keyOf(bob));
        _registerKey(carol, _keyOf(carol));
        _registerKey(dave, _keyOf(dave));
        _registerKey(erin, _keyOf(erin));

        board = abi.decode(_submit(_createCall(chair, 0)), (uint256));
        _submit(_addCall(bob, SEAL_CURRENT, 0));
        _submit(_addCall(carol, SEAL_CURRENT, 0));
    }

    function _keyOf(address account) internal pure returns (bytes memory key) {
        key = new bytes(2592);
        bytes32 word = keccak256(abi.encode("key", account));
        assembly {
            mstore(add(key, 32), word)
        }
    }

    function _createCall(address who, uint256 seed) internal view returns (Call memory c) {
        c.action = CREATE;
        c.account = who;
        c.boardRef = keccak256(abi.encode("board ref", who, registry.createNonces(who), seed));
        c.hashA = keccak256(abi.encode("create envelope", seed));
        c.envelopeSize = ENVELOPE_SIZE;
        c.deadline = uint64(block.timestamp + 600);
    }

    function _addCall(address who, uint8 mode, uint256 seed) internal view returns (Call memory c) {
        uint64 epoch = registry.getBoard(board).epoch;
        c.action = ADD;
        c.boardId = board;
        c.account = who;
        c.mode = mode;
        c.hashA = keccak256(abi.encode("add envelope", who, mode, epoch, seed));
        c.envelopeSize = ENVELOPE_SIZE;
        c.epoch = mode == SEAL_CURRENT ? epoch : epoch + 1;
        c.deadline = uint64(block.timestamp + 600);
    }

    function _removeCall(address who, uint256 seed) internal view returns (Call memory c) {
        uint64 epoch = registry.getBoard(board).epoch;
        c.action = REMOVE;
        c.boardId = board;
        c.account = who;
        c.hashA = keccak256(abi.encode("remove envelope", who, epoch, seed));
        c.envelopeSize = ENVELOPE_SIZE;
        c.epoch = epoch + 1;
        c.deadline = uint64(block.timestamp + 600);
    }

    function _rotateCall(uint256 seed) internal view returns (Call memory c) {
        uint64 epoch = registry.getBoard(board).epoch;
        c.action = ROTATE;
        c.boardId = board;
        c.hashA = keccak256(abi.encode("rotate envelope", epoch, seed));
        c.envelopeSize = ENVELOPE_SIZE;
        c.epoch = epoch + 1;
        c.deadline = uint64(block.timestamp + 600);
    }

    function _postCall(uint256 seed) internal view returns (Call memory c) {
        c.action = POST;
        c.boardId = board;
        c.hashA = keccak256(abi.encode("doc ref", seed));
        c.hashB = keccak256(abi.encode("cipher", seed));
        c.cipherSize = CIPHER_SIZE;
        c.epoch = registry.getBoard(board).epoch;
        c.deadline = uint64(block.timestamp + 600);
    }

    function _transferCall(address to) internal view returns (Call memory c) {
        c.action = TRANSFER;
        c.boardId = board;
        c.account = to;
        c.deadline = uint64(block.timestamp + 600);
    }

    // A valid call for any action code on the fixture, its inputs drawn from `seed`.
    function _actionCall(uint8 action, uint256 seed) internal view returns (Call memory) {
        if (action == CREATE) return _createCall(dave, seed);
        if (action == ADD) return _addCall(seed % 2 == 0 ? dave : erin, uint8(seed / 2 % 2), seed);
        if (action == REMOVE) return _removeCall(seed % 2 == 0 ? bob : carol, seed);
        if (action == ROTATE) return _rotateCall(seed);
        if (action == POST) return _postCall(seed);
        return _transferCall(seed % 2 == 0 ? bob : carol);
    }

    // Built here from the spec, not from the contract, so a contract that encodes differently fails.
    function _paramsHash(Call memory c) internal pure returns (bytes32) {
        if (c.action == CREATE) return keccak256(abi.encode(c.account, c.boardRef, c.hashA, c.envelopeSize));
        if (c.action == ADD) return keccak256(abi.encode(c.account, c.mode, c.hashA, c.envelopeSize, c.epoch));
        if (c.action == REMOVE) return keccak256(abi.encode(c.account, c.hashA, c.envelopeSize, c.epoch));
        if (c.action == ROTATE) return keccak256(abi.encode(c.hashA, c.envelopeSize, c.epoch));
        if (c.action == POST) return keccak256(abi.encode(c.hashA, c.hashB, c.cipherSize, c.epoch));
        return keccak256(abi.encode(c.account));
    }

    function _signer(Call memory c) internal view returns (address) {
        return c.action == CREATE ? c.account : registry.getBoard(c.boardId).chair;
    }

    function _nonce(Call memory c) internal view returns (uint64) {
        return c.action == CREATE ? registry.createNonces(c.account) : registry.getBoard(c.boardId).nonce;
    }

    function _messageOf(Call memory c, uint64 nonce) internal view returns (bytes memory) {
        uint256 boardId = c.action == CREATE ? 0 : c.boardId;
        return abi.encode(SPEC_TAG, block.chainid, address(registry), c.action, boardId, _paramsHash(c), nonce, c.deadline);
    }

    function _signed(Call memory c) internal view returns (bytes memory) {
        return _markerSignature(_keyOf(_signer(c)), _messageOf(c, _nonce(c)));
    }

    function _data(Call memory c, bytes memory sig) internal pure returns (bytes memory) {
        if (c.action == CREATE) {
            return abi.encodeCall(
                BoardRegistry.createBoard, (c.account, c.boardRef, c.hashA, c.envelopeSize, c.deadline, sig)
            );
        }
        if (c.action == ADD) {
            return abi.encodeCall(
                BoardRegistry.addMember,
                (c.boardId, c.account, c.mode, c.hashA, c.envelopeSize, c.epoch, c.deadline, sig)
            );
        }
        if (c.action == REMOVE) {
            return abi.encodeCall(
                BoardRegistry.removeMember, (c.boardId, c.account, c.hashA, c.envelopeSize, c.epoch, c.deadline, sig)
            );
        }
        if (c.action == ROTATE) {
            return abi.encodeCall(BoardRegistry.rotateEpoch, (c.boardId, c.hashA, c.envelopeSize, c.epoch, c.deadline, sig));
        }
        if (c.action == POST) {
            return abi.encodeCall(
                BoardRegistry.postDocument, (c.boardId, c.hashA, c.hashB, c.cipherSize, c.epoch, c.deadline, sig)
            );
        }
        return abi.encodeCall(BoardRegistry.transferChair, (c.boardId, c.account, c.deadline, sig));
    }

    function _try(Call memory c, bytes memory sig) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = address(registry).call(_data(c, sig));
    }

    function _submit(Call memory c) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = _try(c, _signed(c));
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function _badSignature(address signer) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(BoardRegistry.BadSignature.selector, signer);
    }

    // Everything a read can see on the fixture board, plus how many boards exist.
    function _stateDigest() internal view returns (bytes32 h) {
        BoardRegistry.Board memory b = registry.getBoard(board);
        h = keccak256(abi.encode(registry.boardCount(), b, registry.getMembers(board)));
        for (uint64 e; e <= b.epoch + 1; ++e) {
            h = keccak256(abi.encode(h, registry.getGrants(board, e)));
        }
        for (uint256 d; d < b.documentCount; ++d) {
            h = keccak256(abi.encode(h, registry.getDocument(board, d)));
        }
    }

    // The message

    function testFuzz_ActionMessage_Is256BytesAndStartsWith0x20(
        uint8 action,
        uint256 boardId,
        bytes32 paramsHash,
        uint64 nonce,
        uint64 deadline,
        uint256 chainId
    ) public {
        chainId = bound(chainId, 1, MAX_CHAIN_ID);
        vm.chainId(chainId);
        bytes memory m = registry.actionMessage(action, boardId, paramsHash, nonce, deadline);
        assertEq(m.length, 256);
        assertEq(m[0], bytes1(0x20));
        assertEq(m, abi.encode(SPEC_TAG, chainId, address(registry), action, boardId, paramsHash, nonce, deadline));
    }

    function testFuzz_ActionMessage_ChangesWhenAnyOneInputChanges(
        uint8 action,
        uint256 boardId,
        bytes32 paramsHash,
        uint64 nonce,
        uint64 deadline,
        uint256 delta
    ) public {
        bytes32 base = keccak256(registry.actionMessage(action, boardId, paramsHash, nonce, deadline));
        // A nonzero change at each input's own width, so every changed value is a different value.
        uint256 d = bound(delta, 1, type(uint256).max);
        uint8 d8 = uint8(bound(delta, 1, type(uint8).max));
        uint64 d64 = uint64(bound(delta, 1, type(uint64).max));

        assertNotEq(keccak256(registry.actionMessage(action ^ d8, boardId, paramsHash, nonce, deadline)), base, "action");
        assertNotEq(keccak256(registry.actionMessage(action, boardId ^ d, paramsHash, nonce, deadline)), base, "board");
        assertNotEq(
            keccak256(registry.actionMessage(action, boardId, paramsHash ^ bytes32(d), nonce, deadline)), base, "params"
        );
        assertNotEq(keccak256(registry.actionMessage(action, boardId, paramsHash, nonce ^ d64, deadline)), base, "nonce");
        assertNotEq(
            keccak256(registry.actionMessage(action, boardId, paramsHash, nonce, deadline ^ d64)), base, "deadline"
        );
        assertNotEq(
            keccak256(otherRegistry.actionMessage(action, boardId, paramsHash, nonce, deadline)), base, "registry"
        );
        uint256 otherChain = bound(delta, 1, MAX_CHAIN_ID);
        if (otherChain == block.chainid) otherChain = otherChain == 1 ? 2 : otherChain - 1;
        vm.chainId(otherChain);
        assertNotEq(keccak256(registry.actionMessage(action, boardId, paramsHash, nonce, deadline)), base, "chain");
    }

    // The deadline window (C2)

    function testFuzz_Deadline_IsAcceptedExactlyFromNowToAnHourAhead(
        uint8 actionSeed,
        uint64 timestamp,
        uint64 anyDeadline,
        int256 offset,
        uint8 aim
    ) public {
        vm.warp(timestamp);
        uint64 deadline = anyDeadline;
        // A random deadline almost never lands on an edge of a one-hour window, so a third of the runs
        // aim within 3 seconds of now and a third within 3 seconds of an hour ahead.
        if (aim % 3 != 0) {
            int256 edge = int256(uint256(timestamp)) + (aim % 3 == 2 ? int256(HOUR) : int256(0));
            int256 near = edge + bound(offset, -3, 3);
            if (near >= 0 && near <= int256(uint256(type(uint64).max))) deadline = uint64(uint256(near));
        }
        Call memory c = _actionCall(CREATE + actionSeed % 6, actionSeed);
        c.deadline = deadline;
        bytes32 before = _stateDigest();

        (bool ok, bytes memory ret) = _try(c, _signed(c));

        uint256 latest = uint256(timestamp) + HOUR;
        if (deadline >= timestamp && deadline <= latest) {
            assertTrue(ok, "a deadline from now to an hour ahead is accepted");
            return;
        }
        assertFalse(ok);
        if (deadline < timestamp) {
            assertEq(ret, abi.encodeWithSelector(BoardRegistry.DeadlineExpired.selector, deadline, uint256(timestamp)));
        } else {
            assertEq(ret, abi.encodeWithSelector(BoardRegistry.DeadlineTooFar.selector, deadline, latest));
        }
        assertEq(_stateDigest(), before);
    }

    // Size caps (C8)

    function testFuzz_EnvelopeSize_IsAcceptedExactlyFrom1To110000(uint8 actionSeed, uint32 anySize, uint8 aim)
        public
    {
        uint32 size = anySize;
        if (aim % 3 == 1) size = uint32(bound(anySize, 0, 2));
        else if (aim % 3 == 2) size = uint32(bound(anySize, MAX_ENVELOPE_SIZE - 2, MAX_ENVELOPE_SIZE + 2));
        Call memory c = _actionCall(CREATE + actionSeed % 4, actionSeed);
        c.envelopeSize = size;

        (bool ok, bytes memory ret) = _try(c, _signed(c));

        if (size == 0 || size > MAX_ENVELOPE_SIZE) {
            assertFalse(ok);
            assertEq(ret, abi.encodeWithSelector(BoardRegistry.BadEnvelopeSize.selector, size));
            return;
        }
        assertTrue(ok, "an envelope from 1 byte to the cap is accepted");
        uint256 id = c.action == CREATE ? registry.boardCount() : board;
        BoardRegistry.Grant[] memory g = registry.getGrants(id, registry.getBoard(id).epoch);
        assertEq(g[g.length - 1].envelopeSize, size);
    }

    function testFuzz_CipherSize_IsAcceptedExactlyFrom1To25MiB(uint256 seed, uint64 anySize, uint8 aim) public {
        uint64 size = anySize;
        if (aim % 3 == 1) size = uint64(bound(anySize, 0, 2));
        else if (aim % 3 == 2) size = uint64(bound(anySize, MAX_CIPHER_SIZE - 2, MAX_CIPHER_SIZE + 2));
        Call memory c = _postCall(seed);
        c.cipherSize = size;

        (bool ok, bytes memory ret) = _try(c, _signed(c));

        if (size == 0 || size > MAX_CIPHER_SIZE) {
            assertFalse(ok);
            assertEq(ret, abi.encodeWithSelector(BoardRegistry.BadCipherSize.selector, size));
            return;
        }
        assertTrue(ok, "a ciphertext from 1 byte to the cap is accepted");
        assertEq(registry.getDocument(board, 0).cipherSize, size);
    }

    // Signature length (C1)

    function testFuzz_Signature_AnyLengthBut4627IsRefusedAsBadSignature(uint8 actionSeed, uint256 length) public {
        length = bound(length, 0, 20_000);
        vm.assume(length != PQC_ML_DSA_87_SIGNATURE_BYTES);
        Call memory c = _actionCall(CREATE + actionSeed % 6, actionSeed);
        address signer = _signer(c);
        bytes memory sig = _markerSignature(_keyOf(signer), _messageOf(c, _nonce(c)), length);
        bytes32 before = _stateDigest();

        (bool ok, bytes memory ret) = _try(c, sig);
        assertFalse(ok);
        assertEq(ret, _badSignature(signer));

        // The registry's own length check, not only the verifier's: with the verifier saying yes to
        // anything, this length is still refused, while 4,627 bytes of zeros would land.
        vm.mockCall(PQC_VERIFY, abi.encodeWithSelector(IQorePQC.pqcVerify.selector), abi.encode(true));
        (ok, ret) = _try(c, sig);
        assertFalse(ok);
        assertEq(ret, _badSignature(signer));
        assertEq(_stateDigest(), before);
        uint256 snap = vm.snapshotState();
        (bool control,) = _try(c, new bytes(PQC_ML_DSA_87_SIGNATURE_BYTES));
        assertTrue(control, "the stand-in verifier is saying yes to anything");
        vm.revertToState(snap);
        vm.clearMockedCalls();
    }

    // Two actions signed at one nonce (C2, C5, C17)

    // Kinds 0 to 5: add sealed to the current epoch, add with a rotation, remove, rotate, post, transfer.
    function _boardCall(uint8 kind, uint256 seed) internal view returns (Call memory) {
        kind %= 6;
        if (kind < 2) return _addCall(seed % 2 == 0 ? dave : erin, kind, seed);
        if (kind == 2) return _removeCall(seed % 2 == 0 ? bob : carol, seed);
        if (kind == 3) return _rotateCall(seed);
        if (kind == 4) return _postCall(seed);
        return _transferCall(seed % 2 == 0 ? bob : carol);
    }

    function testFuzz_TwoActionsSignedAtOneNonce_OnlyTheFirstLands(
        uint8 firstKind,
        uint8 secondKind,
        uint256 firstSeed,
        uint256 secondSeed
    ) public {
        // Both are built and signed from the same view, as two chair sessions would.
        Call memory first = _boardCall(firstKind, firstSeed);
        Call memory second = _boardCall(secondKind, secondSeed);
        uint64 nonce = registry.getBoard(board).nonce;
        bytes memory firstSig = _signed(first);
        bytes memory secondSig = _signed(second);

        (bool firstOk,) = _try(first, firstSig);
        assertTrue(firstOk, "the first lands");
        assertEq(registry.getBoard(board).nonce, nonce + 1);
        bytes32 afterFirst = _stateDigest();

        (bool secondOk, bytes memory stale) = _try(second, secondSig);
        assertFalse(secondOk, "the second, signed at the same nonce, is refused");
        assertEq(_stateDigest(), afterFirst);

        // Signed again from a fresh view, the same call either lands, so the nonce alone refused the
        // stale one, or fails the same state check the stale one failed before its signature was read.
        uint256 snap = vm.snapshotState();
        (bool freshOk, bytes memory fresh) = _try(second, _signed(second));
        vm.revertToState(snap);
        if (freshOk) assertEq(stale, _badSignature(registry.getBoard(board).chair));
        else assertEq(stale, fresh);
    }
}
