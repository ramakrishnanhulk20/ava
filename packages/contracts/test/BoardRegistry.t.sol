// Does not cover: real ML-DSA-87 maths or the real precompiles (mocks stand in for both; BoardRegistryRealSig.t.sol uses real signatures), the byte-for-byte check against packages/core's test vectors (BoardRegistryVectors.t.sol), or fuzzing and invariant tests (BoardRegistryFuzz.t.sol and the test/invariant/ folder).
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {Vm} from "forge-std/Vm.sol";
import {BoardRegistry} from "../src/BoardRegistry.sol";
import {MockPqcStatus} from "./mocks/MockPqcStatus.sol";
import {MockPqcVerify} from "./mocks/MockPqcVerify.sol";
import {PqcTestKit} from "./helpers/PqcTestKit.sol";

contract BoardRegistryTest is PqcTestKit {
    // Copied from docs/spec/actions.md so the tests never trust the contract's own constant.
    bytes32 internal constant SPEC_TAG = 0x202301722596364529594a8773ff4f11aeb962e112437e042aa0166a90966a17;

    uint8 internal constant CREATE = 1;
    uint8 internal constant ADD = 2;
    uint8 internal constant REMOVE = 3;
    uint8 internal constant ROTATE = 4;
    uint8 internal constant POST = 5;
    uint8 internal constant TRANSFER = 6;
    uint8 internal constant SEAL_CURRENT = 0;
    uint8 internal constant ROTATE_MODE = 1;

    uint64 internal constant T0 = 1_794_787_200;
    uint64 internal constant DEADLINE = T0 + 600;
    uint32 internal constant ENVELOPE_SIZE = 4_985;
    uint64 internal constant CIPHER_SIZE = 40_000;
    bytes32 internal constant DOC_REF = keccak256("doc ref 1");
    bytes32 internal constant CIPHER_HASH = keccak256("cipher 1");

    // Every field any write takes. `account` is the chair for CREATE, the member for ADD and REMOVE,
    // and the new chair for TRANSFER; `hashA` is the envelope hash, or the docRef for POST; `epoch` is
    // epochAfter, or the document's epoch for POST; `boardRef` is used by CREATE only.
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
    MockPqcStatus internal status = MockPqcStatus(PQC_STATUS);
    MockPqcVerify internal verifier = MockPqcVerify(PQC_VERIFY);

    address internal chair = makeAddr("chair");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal dave = makeAddr("dave");
    address internal erin = makeAddr("erin");
    address internal stranger = makeAddr("stranger");
    address internal nokey = makeAddr("nokey");
    address internal relayer = makeAddr("relayer");

    // Two boards of the same shape: chair, bob and carol at epoch 0 with nonce 2.
    uint256 internal board;
    uint256 internal twin;

    function setUp() public {
        vm.warp(T0);
        _etchPqcMocks();
        registry = new BoardRegistry();

        _giveKey(chair);
        _giveKey(bob);
        _giveKey(carol);
        _giveKey(dave);
        _giveKey(erin);
        _giveKey(stranger);

        board = _boardOf(_submit(_createCall(chair)));
        _submit(_addCall(board, bob, SEAL_CURRENT));
        _submit(_addCall(board, carol, SEAL_CURRENT));
        twin = _boardOf(_submit(_createCall(chair)));
        _submit(_addCall(twin, bob, SEAL_CURRENT));
        _submit(_addCall(twin, carol, SEAL_CURRENT));
    }

    function _keyOf(address account) internal pure returns (bytes memory key) {
        key = new bytes(2592);
        bytes32 word = keccak256(abi.encode("key", account));
        assembly {
            mstore(add(key, 32), word)
        }
    }

    // A stand-in signature that, like a real one, belongs to one signer and one message.
    function _sigFor(address signer, bytes memory message) internal pure returns (bytes memory sig) {
        sig = new bytes(4627);
        bytes32 word = keccak256(abi.encode("sig", signer, message));
        assembly {
            mstore(add(sig, 32), word)
        }
    }

    function _giveKey(address account) internal {
        _registerKey(account, _keyOf(account));
    }

    function _sign(address signer, bytes memory message) internal returns (bytes memory sig) {
        sig = _sigFor(signer, message);
        _registerTriple(_keyOf(signer), sig, message);
    }

    function _createCall(address who) internal view returns (Call memory c) {
        c.action = CREATE;
        c.account = who;
        c.boardRef = keccak256(abi.encode("board ref", who, registry.createNonces(who)));
        c.hashA = keccak256(abi.encode("create envelope", who));
        c.envelopeSize = ENVELOPE_SIZE;
        c.deadline = DEADLINE;
    }

    function _addCall(uint256 id, address who, uint8 mode) internal view returns (Call memory c) {
        uint64 epoch = registry.getBoard(id).epoch;
        c.action = ADD;
        c.boardId = id;
        c.account = who;
        c.mode = mode;
        c.hashA = keccak256(abi.encode("add envelope", id, who, mode, epoch));
        c.envelopeSize = ENVELOPE_SIZE;
        c.epoch = mode == SEAL_CURRENT ? epoch : epoch + 1;
        c.deadline = DEADLINE;
    }

    function _removeCall(uint256 id, address who) internal view returns (Call memory c) {
        uint64 epoch = registry.getBoard(id).epoch;
        c.action = REMOVE;
        c.boardId = id;
        c.account = who;
        c.hashA = keccak256(abi.encode("remove envelope", id, who, epoch));
        c.envelopeSize = ENVELOPE_SIZE;
        c.epoch = epoch + 1;
        c.deadline = DEADLINE;
    }

    function _rotateCall(uint256 id) internal view returns (Call memory c) {
        uint64 epoch = registry.getBoard(id).epoch;
        c.action = ROTATE;
        c.boardId = id;
        c.hashA = keccak256(abi.encode("rotate envelope", id, epoch));
        c.envelopeSize = ENVELOPE_SIZE;
        c.epoch = epoch + 1;
        c.deadline = DEADLINE;
    }

    function _postCall(uint256 id, bytes32 docRef) internal view returns (Call memory c) {
        c.action = POST;
        c.boardId = id;
        c.hashA = docRef;
        c.hashB = CIPHER_HASH;
        c.cipherSize = CIPHER_SIZE;
        c.epoch = registry.getBoard(id).epoch;
        c.deadline = DEADLINE;
    }

    function _transferCall(uint256 id, address to) internal pure returns (Call memory c) {
        c.action = TRANSFER;
        c.boardId = id;
        c.account = to;
        c.deadline = DEADLINE;
    }

    // The fixture's standard call for each action, on `board`.
    function _defaultCall(uint8 action) internal view returns (Call memory) {
        if (action == CREATE) return _createCall(chair);
        if (action == ADD) return _addCall(board, dave, SEAL_CURRENT);
        if (action == REMOVE) return _removeCall(board, bob);
        if (action == ROTATE) return _rotateCall(board);
        if (action == POST) return _postCall(board, DOC_REF);
        return _transferCall(board, bob);
    }

    function _clone(Call memory c) internal pure returns (Call memory) {
        return Call(
            c.action,
            c.boardId,
            c.account,
            c.mode,
            c.hashA,
            c.hashB,
            c.envelopeSize,
            c.cipherSize,
            c.epoch,
            c.deadline,
            c.boardRef
        );
    }

    function _name(uint8 action) internal pure returns (string memory) {
        if (action == CREATE) return "createBoard";
        if (action == ADD) return "addMember";
        if (action == REMOVE) return "removeMember";
        if (action == ROTATE) return "rotateEpoch";
        if (action == POST) return "postDocument";
        return "transferChair";
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
        if (c.action == CREATE) return c.account;
        return registry.exists(c.boardId) ? registry.getBoard(c.boardId).chair : address(0);
    }

    function _nonce(Call memory c) internal view returns (uint64) {
        if (c.action == CREATE) return registry.createNonces(c.account);
        return registry.exists(c.boardId) ? registry.getBoard(c.boardId).nonce : 0;
    }

    function _rawMessage(
        uint256 chainId,
        address registryAddress,
        uint8 action,
        uint256 boardId,
        bytes32 paramsHash,
        uint64 nonce,
        uint64 deadline
    ) internal pure returns (bytes memory) {
        return abi.encode(SPEC_TAG, chainId, registryAddress, action, boardId, paramsHash, nonce, deadline);
    }

    function _messageOf(Call memory c, uint64 nonce) internal view returns (bytes memory) {
        uint256 boardId = c.action == CREATE ? 0 : c.boardId;
        return _rawMessage(block.chainid, address(registry), c.action, boardId, _paramsHash(c), nonce, c.deadline);
    }

    function _signed(Call memory c) internal returns (bytes memory) {
        return _sign(_signer(c), _messageOf(c, _nonce(c)));
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

    function _submit(Call memory c, bytes memory sig) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = _try(c, sig);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function _submit(Call memory c) internal returns (bytes memory) {
        return _submit(c, _signed(c));
    }

    function _assertRefused(Call memory c, bytes memory sig, bytes memory expected) internal {
        (bool ok, bytes memory ret) = _try(c, sig);
        assertFalse(ok, _name(c.action));
        assertEq(ret, expected, _name(c.action));
    }

    function _assertRefused(Call memory c, bytes memory expected) internal {
        _assertRefused(c, _signed(c), expected);
    }

    function _boardOf(bytes memory ret) internal pure returns (uint256) {
        return abi.decode(ret, (uint256));
    }

    function _err(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(selector);
    }

    function _err(bytes4 selector, uint256 a) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(selector, a);
    }

    function _err(bytes4 selector, address a) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(selector, a);
    }

    function _err(bytes4 selector, uint256 a, address b) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(selector, a, b);
    }

    function _badSignature(address signer) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(BoardRegistry.BadSignature.selector, signer);
    }

    function _wrongEpoch(uint64 expected, uint64 given) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(BoardRegistry.WrongEpoch.selector, expected, given);
    }

    function _assertMembers(uint256 id, address[] memory expected) internal view {
        address[] memory actual = registry.getMembers(id);
        assertEq(actual, expected);
        assertEq(registry.getBoard(id).memberCount, expected.length);
        for (uint256 i; i < expected.length; ++i) {
            assertTrue(registry.isMember(id, expected[i]));
        }
    }

    function _list(address a, address b) internal pure returns (address[] memory l) {
        l = new address[](2);
        (l[0], l[1]) = (a, b);
    }

    function _list(address a, address b, address c) internal pure returns (address[] memory l) {
        l = new address[](3);
        (l[0], l[1], l[2]) = (a, b, c);
    }

    function _list(address a, address b, address c, address d) internal pure returns (address[] memory l) {
        l = new address[](4);
        (l[0], l[1], l[2], l[3]) = (a, b, c, d);
    }

    // The test's own expectEmit lines are logs too, so count only the registry's.
    function _registryLogCount() internal view returns (uint256 count) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(registry)) ++count;
        }
    }

    function _assertGrant(BoardRegistry.Grant memory g, Call memory c, uint8 mode, address member) internal pure {
        assertEq(g.envelopeHash, c.hashA);
        assertEq(g.envelopeSize, c.envelopeSize);
        assertEq(g.mode, mode);
        assertEq(g.member, member);
    }

    // createBoard

    function test_Create_StartsABoardAtEpoch0WithTheChairAsItsOnlyMember() public {
        Call memory c = _createCall(dave);
        bytes memory sig = _signed(c);

        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.BoardCreated(3, dave, c.boardRef, 0);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.EnvelopeGranted(3, 0, c.hashA, ENVELOPE_SIZE, ROTATE_MODE, address(0), 0);
        uint256 id = _boardOf(_submit(c, sig));

        assertEq(id, 3);
        assertEq(registry.boardCount(), 3);
        assertTrue(registry.exists(3));
        assertEq(registry.createNonces(dave), 1);
        BoardRegistry.Board memory b = registry.getBoard(3);
        assertEq(b.chair, dave);
        assertEq(b.boardRef, c.boardRef);
        assertEq(registry.boardIdOf(c.boardRef), 3);
        assertEq(b.epoch, 0);
        assertEq(b.nonce, 0);
        assertEq(b.memberCount, 1);
        assertEq(b.documentCount, 0);
        address[] memory only = new address[](1);
        only[0] = dave;
        _assertMembers(3, only);
        BoardRegistry.Grant[] memory g = registry.getGrants(3, 0);
        assertEq(g.length, 1);
        _assertGrant(g[0], c, ROTATE_MODE, address(0));
    }

    function test_Create_NumbersBoardsFromOneWithACreationNoncePerChair() public {
        assertFalse(registry.exists(0));
        assertTrue(registry.exists(1));
        assertTrue(registry.exists(2));
        assertFalse(registry.exists(3));
        assertEq(registry.createNonces(chair), 2);
        assertEq(registry.createNonces(dave), 0);

        Call memory byChair = _createCall(chair);
        bytes memory chairSig = _signed(byChair);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.BoardCreated(3, chair, byChair.boardRef, 2);
        assertEq(_boardOf(_submit(byChair, chairSig)), 3);

        Call memory byDave = _createCall(dave);
        bytes memory daveSig = _signed(byDave);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.BoardCreated(4, dave, byDave.boardRef, 0);
        assertEq(_boardOf(_submit(byDave, daveSig)), 4);

        assertEq(registry.createNonces(chair), 3);
        assertEq(registry.createNonces(dave), 1);
        assertEq(registry.boardCount(), 4);
    }

    function test_Create_RefusesTheZeroChair() public {
        _assertRefused(_createCall(address(0)), _err(BoardRegistry.ZeroAddress.selector));
    }

    function test_Create_RefusesAChairWithNoKey() public {
        _assertRefused(_createCall(nokey), _err(BoardRegistry.NoPqcKey.selector, nokey));
    }

    function test_Create_ReplayIsRefusedByTheUsedBoardRefAndByTheMovedNonce() public {
        Call memory c = _createCall(dave);
        Call memory unusedRef = _clone(c);
        unusedRef.boardRef = keccak256("another board ref");
        bytes memory sig = _signed(c);
        bytes memory unusedRefSig = _signed(unusedRef);
        _submit(c, sig);

        _assertRefused(c, sig, abi.encodeWithSelector(BoardRegistry.BoardRefUsed.selector, c.boardRef));
        // A signature over an unused boardRef made at the old nonce fails on the nonce alone.
        bytes memory next = _messageOf(unusedRef, 1);
        vm.expectCall(PQC_VERIFY, abi.encodeCall(MockPqcVerify.pqcVerify, (_keyOf(dave), unusedRefSig, next)));
        _assertRefused(unusedRef, unusedRefSig, _badSignature(dave));
        assertEq(registry.boardCount(), 3);
        assertEq(registry.createNonces(dave), 1);
    }

    function test_Create_FindsEveryBoardByItsBoardRef() public view {
        bytes32 boardRef = registry.getBoard(board).boardRef;
        bytes32 twinRef = registry.getBoard(twin).boardRef;
        assertNotEq(boardRef, twinRef);
        assertEq(registry.boardIdOf(boardRef), board);
        assertEq(registry.boardIdOf(twinRef), twin);
        assertEq(registry.boardIdOf(keccak256("never used")), 0);
        assertEq(registry.boardIdOf(bytes32(0)), 0);
    }

    function test_Create_RefusesAZeroBoardRef() public {
        Call memory c = _createCall(dave);
        c.boardRef = bytes32(0);
        _assertRefused(c, _err(BoardRegistry.ZeroHash.selector));
    }

    function test_Create_RefusesABoardRefAlreadyUsedByAnyChair() public {
        bytes32 used = registry.getBoard(board).boardRef;
        bytes memory expected = abi.encodeWithSelector(BoardRegistry.BoardRefUsed.selector, used);
        Call memory byDave = _createCall(dave);
        byDave.boardRef = used;
        _assertRefused(byDave, expected);
        Call memory byChair = _createCall(chair);
        byChair.boardRef = used;
        _assertRefused(byChair, expected);
    }

    function test_Create_TheSignatureCoversTheBoardRef() public {
        Call memory c = _createCall(dave);
        bytes memory sig = _signed(c);
        Call memory otherRef = _clone(c);
        otherRef.boardRef = keccak256("another board ref");
        _assertRefused(otherRef, sig, _badSignature(dave));
        _submit(c, sig);
        assertEq(registry.boardIdOf(c.boardRef), 3);
    }

    // addMember

    function test_Add_SealCurrentAppendsAGrantForTheNewMemberAndKeepsTheEpoch() public {
        Call memory c = _addCall(board, dave, SEAL_CURRENT);
        bytes memory sig = _signed(c);
        BoardRegistry.Grant[] memory before = registry.getGrants(board, 0);

        vm.recordLogs();
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.MemberAdded(board, dave, 0, SEAL_CURRENT, 2);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.EnvelopeGranted(board, 0, c.hashA, ENVELOPE_SIZE, SEAL_CURRENT, dave, 2);
        _submit(c, sig);
        assertEq(_registryLogCount(), 2, "no EpochRotated for a seal-current add");

        BoardRegistry.Board memory b = registry.getBoard(board);
        assertEq(b.epoch, 0);
        assertEq(b.nonce, 3);
        _assertMembers(board, _list(chair, bob, carol, dave));
        BoardRegistry.Grant[] memory g = registry.getGrants(board, 0);
        assertEq(g.length, before.length + 1);
        _assertGrant(g[before.length], c, SEAL_CURRENT, dave);
    }

    function test_Add_RotateMovesTheEpochAndOpensItsGrantList() public {
        Call memory c = _addCall(board, dave, ROTATE_MODE);
        bytes memory sig = _signed(c);

        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.MemberAdded(board, dave, 1, ROTATE_MODE, 2);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.EpochRotated(board, 1, 2);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.EnvelopeGranted(board, 1, c.hashA, ENVELOPE_SIZE, ROTATE_MODE, address(0), 2);
        _submit(c, sig);

        BoardRegistry.Board memory b = registry.getBoard(board);
        assertEq(b.epoch, 1);
        assertEq(b.nonce, 3);
        _assertMembers(board, _list(chair, bob, carol, dave));
        BoardRegistry.Grant[] memory g = registry.getGrants(board, 1);
        assertEq(g.length, 1);
        _assertGrant(g[0], c, ROTATE_MODE, address(0));
        assertEq(registry.getGrants(board, 0).length, 3);
    }

    function test_Add_GrantsAreAppendOnly() public {
        BoardRegistry.Grant[] memory before = registry.getGrants(board, 0);
        assertEq(before.length, 3);

        Call memory addDave = _addCall(board, dave, SEAL_CURRENT);
        _submit(addDave);
        Call memory addErin = _addCall(board, erin, SEAL_CURRENT);
        _submit(addErin);
        _submit(_rotateCall(board));
        Call memory addStranger = _addCall(board, stranger, SEAL_CURRENT);
        _submit(addStranger);

        BoardRegistry.Grant[] memory epoch0 = registry.getGrants(board, 0);
        assertEq(epoch0.length, 5);
        for (uint256 i; i < before.length; ++i) {
            assertEq(abi.encode(epoch0[i]), abi.encode(before[i]), "an earlier grant changed");
        }
        _assertGrant(epoch0[3], addDave, SEAL_CURRENT, dave);
        _assertGrant(epoch0[4], addErin, SEAL_CURRENT, erin);
        BoardRegistry.Grant[] memory epoch1 = registry.getGrants(board, 1);
        assertEq(epoch1.length, 2);
        assertEq(epoch1[0].mode, ROTATE_MODE);
        _assertGrant(epoch1[1], addStranger, SEAL_CURRENT, stranger);
    }

    function test_Add_RefusesTheZeroAddress() public {
        _assertRefused(_addCall(board, address(0), SEAL_CURRENT), _err(BoardRegistry.ZeroAddress.selector));
    }

    function test_Add_RefusesAnExistingMemberAndTheChair() public {
        _assertRefused(_addCall(board, bob, SEAL_CURRENT), _err(BoardRegistry.AlreadyMember.selector, board, bob));
        _assertRefused(_addCall(board, chair, ROTATE_MODE), _err(BoardRegistry.AlreadyMember.selector, board, chair));
    }

    function test_Add_RefusesAnUnknownMode() public {
        Call memory c = _addCall(board, dave, SEAL_CURRENT);
        c.mode = 2;
        _assertRefused(c, abi.encodeWithSelector(BoardRegistry.BadMode.selector, uint8(2)));
    }

    function test_Add_SealCurrentRefusesAnyEpochButTheCurrentOne() public {
        Call memory c = _addCall(board, dave, SEAL_CURRENT);
        c.epoch = 1;
        _assertRefused(c, _wrongEpoch(0, 1));
    }

    function test_Add_RotateRefusesAnyEpochButTheNextOne() public {
        Call memory c = _addCall(board, dave, ROTATE_MODE);
        c.epoch = 0;
        _assertRefused(c, _wrongEpoch(1, 0));
        c.epoch = 2;
        _assertRefused(c, _wrongEpoch(1, 2));
    }

    function test_Add_RefusesAMemberWithNoKey() public {
        _assertRefused(_addCall(board, nokey, SEAL_CURRENT), _err(BoardRegistry.NoPqcKey.selector, nokey));
    }

    function test_Add_RefusesAMemberWhoseKeyIsNotMlDsa87() public {
        status.setKey(dave, true, 3, _keyOf(dave), true);
        _assertRefused(
            _addCall(board, dave, SEAL_CURRENT),
            abi.encodeWithSelector(BoardRegistry.WrongAlgorithm.selector, dave, uint8(3))
        );
    }

    function test_Add_RefusesAMemberWithoutProofOfPossession() public {
        status.setKey(dave, true, 1, _keyOf(dave), false);
        _assertRefused(_addCall(board, dave, SEAL_CURRENT), _err(BoardRegistry.PossessionNotProven.selector, dave));
    }

    function test_Add_RefusesAMemberWhoseKeyIsNot2592Bytes() public {
        status.setKey(dave, true, 1, new bytes(2591), true);
        _assertRefused(
            _addCall(board, dave, SEAL_CURRENT),
            abi.encodeWithSelector(BoardRegistry.BadKeyLength.selector, dave, uint256(2591))
        );
    }

    function test_Add_FillsToMaxMembersThenRefusesUntilARemoval() public {
        uint256 max = registry.MAX_MEMBERS();
        assertEq(max, 64);
        for (uint256 i = 3; i < max; ++i) {
            address member = makeAddr(string.concat("member ", vm.toString(i)));
            _giveKey(member);
            _submit(_addCall(board, member, SEAL_CURRENT));
        }
        assertEq(registry.getBoard(board).memberCount, max);
        assertEq(registry.getMembers(board).length, max);
        assertEq(registry.getGrants(board, 0).length, max, "grants per epoch stay within MAX_MEMBERS");

        _assertRefused(_addCall(board, dave, SEAL_CURRENT), abi.encodeWithSelector(BoardRegistry.BoardFull.selector, board, max));
        _assertRefused(_addCall(board, dave, ROTATE_MODE), abi.encodeWithSelector(BoardRegistry.BoardFull.selector, board, max));

        _submit(_removeCall(board, bob));
        _submit(_addCall(board, dave, SEAL_CURRENT));
        assertEq(registry.getBoard(board).memberCount, max);
        assertTrue(registry.isMember(board, dave));
    }

    // removeMember

    function test_Remove_DropsTheMemberAndMovesTheEpoch() public {
        Call memory c = _removeCall(board, bob);
        bytes memory sig = _signed(c);

        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.MemberRemoved(board, bob, 1, 2);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.EpochRotated(board, 1, 2);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.EnvelopeGranted(board, 1, c.hashA, ENVELOPE_SIZE, ROTATE_MODE, address(0), 2);
        _submit(c, sig);

        BoardRegistry.Board memory b = registry.getBoard(board);
        assertEq(b.epoch, 1);
        assertEq(b.nonce, 3);
        assertFalse(registry.isMember(board, bob));
        _assertMembers(board, _list(chair, carol));
        BoardRegistry.Grant[] memory g = registry.getGrants(board, 1);
        assertEq(g.length, 1);
        _assertGrant(g[0], c, ROTATE_MODE, address(0));
        assertEq(registry.getGrants(board, 0).length, 3);
    }

    function test_Remove_TheChairCannotBeRemoved() public {
        _assertRefused(_removeCall(board, chair), _err(BoardRegistry.ChairCannotLeave.selector, board, chair));
    }

    function test_Remove_RefusesANonMember() public {
        _assertRefused(_removeCall(board, dave), _err(BoardRegistry.NotMember.selector, board, dave));
    }

    function test_Remove_RefusesTheZeroAddress() public {
        _assertRefused(_removeCall(board, address(0)), _err(BoardRegistry.ZeroAddress.selector));
    }

    function test_Remove_RefusesAnyEpochButTheNextOne() public {
        Call memory c = _removeCall(board, bob);
        c.epoch = 0;
        _assertRefused(c, _wrongEpoch(1, 0));
        c.epoch = 2;
        _assertRefused(c, _wrongEpoch(1, 2));
    }

    function test_Remove_SwapAndPopKeepsTheSetRightWhenTheFirstMemberLeaves() public {
        _submit(_addCall(board, dave, SEAL_CURRENT));
        _submit(_transferCall(board, bob));
        _submit(_removeCall(board, chair));
        _assertMembers(board, _list(dave, bob, carol));
        assertFalse(registry.isMember(board, chair));

        _submit(_removeCall(board, dave));
        _assertMembers(board, _list(carol, bob));
        assertFalse(registry.isMember(board, dave));

        _submit(_addCall(board, chair, SEAL_CURRENT));
        _assertMembers(board, _list(carol, bob, chair));
    }

    function test_Remove_SwapAndPopKeepsTheSetRightWhenAMiddleMemberLeaves() public {
        _submit(_addCall(board, dave, SEAL_CURRENT));
        _submit(_removeCall(board, bob));
        _assertMembers(board, _list(chair, dave, carol));
        assertFalse(registry.isMember(board, bob));

        // dave moved into bob's slot, so removing dave proves his position was updated.
        _submit(_removeCall(board, dave));
        _assertMembers(board, _list(chair, carol));
        assertFalse(registry.isMember(board, dave));

        _submit(_addCall(board, bob, SEAL_CURRENT));
        _assertMembers(board, _list(chair, carol, bob));
    }

    function test_Remove_SwapAndPopKeepsTheSetRightWhenTheLastMemberLeaves() public {
        _submit(_addCall(board, dave, SEAL_CURRENT));
        _submit(_removeCall(board, dave));
        _assertMembers(board, _list(chair, bob, carol));
        assertFalse(registry.isMember(board, dave));

        _submit(_removeCall(board, carol));
        _assertMembers(board, _list(chair, bob));

        _submit(_addCall(board, dave, SEAL_CURRENT));
        _assertMembers(board, _list(chair, bob, dave));
        _assertRefused(_addCall(board, dave, SEAL_CURRENT), _err(BoardRegistry.AlreadyMember.selector, board, dave));
    }

    // rotateEpoch

    function test_Rotate_MovesTheEpochByOneAndKeepsTheMembers() public {
        Call memory c = _rotateCall(board);
        bytes memory sig = _signed(c);

        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.EpochRotated(board, 1, 2);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.EnvelopeGranted(board, 1, c.hashA, ENVELOPE_SIZE, ROTATE_MODE, address(0), 2);
        _submit(c, sig);

        BoardRegistry.Board memory b = registry.getBoard(board);
        assertEq(b.epoch, 1);
        assertEq(b.nonce, 3);
        _assertMembers(board, _list(chair, bob, carol));
        BoardRegistry.Grant[] memory g = registry.getGrants(board, 1);
        assertEq(g.length, 1);
        _assertGrant(g[0], c, ROTATE_MODE, address(0));
        assertEq(registry.getGrants(board, 0).length, 3);
    }

    function test_Rotate_RefusesAnyEpochButTheNextOne() public {
        Call memory c = _rotateCall(board);
        c.epoch = 0;
        _assertRefused(c, _wrongEpoch(1, 0));
        c.epoch = 2;
        _assertRefused(c, _wrongEpoch(1, 2));
    }

    function test_Rotate_AFreshSignatureForAnEpochAlreadyReachedIsRefused() public {
        Call memory c = _rotateCall(board);
        _submit(c);
        _assertRefused(c, _wrongEpoch(2, 1));
        _submit(_rotateCall(board));
        assertEq(registry.getBoard(board).epoch, 2);
    }

    // postDocument

    function test_Post_RecordsTheDocumentUnderTheCurrentEpochAndNeverChangesIt() public {
        Call memory c = _postCall(board, DOC_REF);
        bytes memory sig = _signed(c);

        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.DocumentPosted(board, 0, DOC_REF, 0, CIPHER_HASH, CIPHER_SIZE, 2);
        assertEq(abi.decode(_submit(c, sig), (uint256)), 0);

        BoardRegistry.Board memory b = registry.getBoard(board);
        assertEq(b.documentCount, 1);
        assertEq(b.nonce, 3);
        assertEq(b.epoch, 0);
        BoardRegistry.Document memory d = registry.getDocument(board, 0);
        assertEq(d.docRef, DOC_REF);
        assertEq(d.cipherHash, CIPHER_HASH);
        assertEq(d.cipherSize, CIPHER_SIZE);
        assertEq(d.epoch, 0);
        assertEq(d.postedAt, T0);

        _submit(_rotateCall(board));
        Call memory second = _postCall(board, keccak256("doc ref 2"));
        bytes memory secondSig = _signed(second);
        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.DocumentPosted(board, 1, second.hashA, 1, CIPHER_HASH, CIPHER_SIZE, 4);
        assertEq(abi.decode(_submit(second, secondSig), (uint256)), 1);

        assertEq(abi.encode(registry.getDocument(board, 0)), abi.encode(d), "an earlier document changed");
        assertEq(registry.getDocument(board, 1).epoch, 1);
        assertEq(registry.getBoard(board).documentCount, 2);
    }

    function test_Post_RefusesAZeroDocRefOrCipherHash() public {
        _assertRefused(_postCall(board, bytes32(0)), _err(BoardRegistry.ZeroHash.selector));
        Call memory c = _postCall(board, DOC_REF);
        c.hashB = bytes32(0);
        _assertRefused(c, _err(BoardRegistry.ZeroHash.selector));
    }

    function test_Post_RefusesACipherSizeOf0OrAboveTheCap() public {
        Call memory c = _postCall(board, DOC_REF);
        c.cipherSize = 0;
        _assertRefused(c, abi.encodeWithSelector(BoardRegistry.BadCipherSize.selector, uint64(0)));
        c.cipherSize = registry.MAX_CIPHER_SIZE() + 1;
        _assertRefused(c, abi.encodeWithSelector(BoardRegistry.BadCipherSize.selector, c.cipherSize));
    }

    function test_Post_AcceptsTheLargestCiphertext() public {
        Call memory c = _postCall(board, DOC_REF);
        c.cipherSize = 26_214_400;
        _submit(c);
        assertEq(registry.getDocument(board, 0).cipherSize, 26_214_400);
    }

    function test_Post_RefusesAnyEpochButTheCurrentOne() public {
        Call memory c = _postCall(board, DOC_REF);
        c.epoch = 1;
        _assertRefused(c, _wrongEpoch(0, 1));

        _submit(_rotateCall(board));
        c.epoch = 0;
        _assertRefused(c, _wrongEpoch(1, 0));
    }

    function test_Post_SignedForEpochEIsRefusedOnceARemovalMovesTheBoardToEPlus1() public {
        Call memory post = _postCall(board, DOC_REF);
        bytes memory postSig = _signed(post);
        Call memory removal = _removeCall(board, bob);
        bytes memory removalSig = _signed(removal);

        _submit(removal, removalSig);
        _assertRefused(post, postSig, _wrongEpoch(1, 0));
        // A signature made after the removal for the old epoch is refused as well.
        _assertRefused(post, _wrongEpoch(1, 0));
        assertEq(registry.getBoard(board).documentCount, 0);
    }

    function test_Post_RefusesADocRefAlreadyUsedOnTheBoard() public {
        _submit(_postCall(board, DOC_REF));
        Call memory again = _postCall(board, DOC_REF);
        again.hashB = keccak256("other cipher");
        _assertRefused(again, abi.encodeWithSelector(BoardRegistry.DocRefUsed.selector, board, DOC_REF));
    }

    function test_Post_TheSameDocRefIsFineOnAnotherBoard() public {
        _submit(_postCall(board, DOC_REF));
        _submit(_postCall(twin, DOC_REF));
        assertEq(registry.getDocument(twin, 0).docRef, DOC_REF);
    }

    function test_GetDocument_RevertsPastTheLastDocument() public {
        vm.expectRevert(abi.encodeWithSelector(BoardRegistry.UnknownDocument.selector, board, uint256(0)));
        registry.getDocument(board, 0);
    }

    function test_GetDocument_RevertsUnknownDocumentFromDocumentCountUp() public {
        _submit(_postCall(board, DOC_REF));
        assertEq(registry.getDocument(board, 0).docRef, DOC_REF);
        vm.expectRevert(abi.encodeWithSelector(BoardRegistry.UnknownDocument.selector, board, uint256(1)));
        registry.getDocument(board, 1);
        vm.expectRevert(abi.encodeWithSelector(BoardRegistry.UnknownDocument.selector, board, type(uint256).max));
        registry.getDocument(board, type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(BoardRegistry.UnknownDocument.selector, twin, uint256(0)));
        registry.getDocument(twin, 0);
    }

    // transferChair

    function test_Transfer_HandsTheChairToAMemberAndKeepsEverythingElse() public {
        Call memory c = _transferCall(board, bob);
        bytes memory sig = _signed(c);

        vm.expectEmit(true, true, true, true, address(registry));
        emit BoardRegistry.ChairTransferred(board, chair, bob, 2);
        _submit(c, sig);

        BoardRegistry.Board memory b = registry.getBoard(board);
        assertEq(b.chair, bob);
        assertEq(b.nonce, 3);
        assertEq(b.epoch, 0);
        _assertMembers(board, _list(chair, bob, carol));
        assertEq(registry.getGrants(board, 0).length, 3);
    }

    function test_Transfer_OnlyTheNewChairCanSignAfterwards() public {
        _submit(_transferCall(board, bob));

        Call memory rotate = _rotateCall(board);
        bytes memory oldChairSig = _sign(chair, _messageOf(rotate, 3));
        _assertRefused(rotate, oldChairSig, _badSignature(bob));
        _submit(rotate);
        assertEq(registry.getBoard(board).epoch, 1);

        _assertRefused(_removeCall(board, bob), _err(BoardRegistry.ChairCannotLeave.selector, board, bob));
        _submit(_removeCall(board, chair));
        assertFalse(registry.isMember(board, chair));
    }

    function test_Transfer_RefusesTheZeroAddress() public {
        _assertRefused(_transferCall(board, address(0)), _err(BoardRegistry.ZeroAddress.selector));
    }

    function test_Transfer_RefusesTheCurrentChair() public {
        _assertRefused(_transferCall(board, chair), _err(BoardRegistry.SameChair.selector, board, chair));
    }

    function test_Transfer_RefusesAnAccountThatIsNotAMember() public {
        _assertRefused(_transferCall(board, stranger), _err(BoardRegistry.NotMember.selector, board, stranger));
    }

    function test_Transfer_RefusesANewChairWhoseKeyIsNoLongerRegistered() public {
        status.setKey(bob, false, 0, "", false);
        _assertRefused(_transferCall(board, bob), _err(BoardRegistry.NoPqcKey.selector, bob));
    }

    function test_Transfer_RefusesANewChairWhoseKeyIsNotMlDsa87() public {
        status.setKey(bob, true, 2, _keyOf(bob), true);
        _assertRefused(
            _transferCall(board, bob), abi.encodeWithSelector(BoardRegistry.WrongAlgorithm.selector, bob, uint8(2))
        );
    }

    function test_Transfer_RefusesANewChairWithoutProofOfPossession() public {
        status.setKey(bob, true, 1, _keyOf(bob), false);
        _assertRefused(_transferCall(board, bob), _err(BoardRegistry.PossessionNotProven.selector, bob));
    }

    function test_Transfer_RefusesANewChairWhoseKeyIsNot2592Bytes() public {
        status.setKey(bob, true, 1, new bytes(2593), true);
        _assertRefused(
            _transferCall(board, bob),
            abi.encodeWithSelector(BoardRegistry.BadKeyLength.selector, bob, uint256(2593))
        );
    }

    // Every write: authority, replay and confusion

    function _isEnvelopeWrite(uint8 action) internal pure returns (bool) {
        return action == CREATE || action == ADD || action == REMOVE || action == ROTATE;
    }

    // One changed copy per signed parameter that can change while every other check still passes.
    function _mutations(Call memory c) internal view returns (Call[] memory list) {
        list = new Call[](4);
        uint256 n;
        if (c.action == CREATE) {
            list[n] = _clone(c);
            list[n++].account = stranger;
            list[n] = _clone(c);
            list[n++].boardRef = keccak256("another board ref");
        } else if (c.action == ADD) {
            list[n] = _clone(c);
            list[n++].account = erin;
            list[n] = _clone(c);
            (list[n].mode, list[n].epoch) = (ROTATE_MODE, c.epoch + 1);
            ++n;
        } else if (c.action == REMOVE) {
            list[n] = _clone(c);
            list[n++].account = carol;
        } else if (c.action == POST) {
            list[n] = _clone(c);
            list[n++].hashA = keccak256("another doc ref");
            list[n] = _clone(c);
            list[n++].hashB = keccak256("another cipher");
            list[n] = _clone(c);
            list[n++].cipherSize = c.cipherSize + 1;
        } else if (c.action == TRANSFER) {
            list[n] = _clone(c);
            list[n++].account = carol;
        }
        if (_isEnvelopeWrite(c.action)) {
            list[n] = _clone(c);
            list[n++].hashA = keccak256("another envelope");
            list[n] = _clone(c);
            list[n++].envelopeSize = c.envelopeSize + 1;
        }
        assembly {
            mstore(list, n)
        }
    }

    function test_EveryWrite_AnySenderMaySubmitAndTheNonceMovesByExactlyOne() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            uint256 snap = vm.snapshotState();
            Call memory c = _defaultCall(a);
            bytes memory sig = _signed(c);
            uint64 before = _nonce(c);

            vm.prank(relayer);
            (bool ok,) = _try(c, sig);
            assertTrue(ok, _name(a));
            assertEq(_nonce(c), before + 1, _name(a));
            if (a == CREATE) assertEq(registry.getBoard(3).nonce, 0, "a new board starts at nonce 0");
            vm.revertToState(snap);
        }
    }

    function test_EveryWrite_TheSenderBeingTheChairGrantsNothing() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            bytes memory unsigned = _sigFor(chair, _messageOf(c, _nonce(c)));
            vm.prank(chair);
            _assertRefused(c, unsigned, _badSignature(chair));
        }
    }

    function test_EveryWrite_RefusesAReplayOfTheCallThatLanded() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            uint256 snap = vm.snapshotState();
            Call memory c = _defaultCall(a);
            bytes memory sig = _signed(c);
            _submit(c, sig);
            uint64 landedNonce = _nonce(c);

            (bool ok,) = _try(c, sig);
            assertFalse(ok, _name(a));
            assertEq(_nonce(c), landedNonce, _name(a));
            vm.revertToState(snap);
        }
    }

    function test_EveryWrite_RefusesItsSignatureOnceTheNonceHasMoved() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            uint256 snap = vm.snapshotState();
            Call memory c = _defaultCall(a);
            bytes memory sig = _signed(c);

            if (a == CREATE) {
                Call memory otherBoard = _createCall(chair);
                otherBoard.boardRef = keccak256("another board ref");
                _submit(otherBoard);
            } else {
                _submit(_postCall(board, keccak256("another doc ref")));
            }
            _assertRefused(c, sig, _badSignature(chair));
            vm.revertToState(snap);
        }
    }

    function test_EveryBoardWrite_RefusesASignatureMadeForAnotherBoard() public {
        assertEq(registry.getBoard(twin).nonce, registry.getBoard(board).nonce);
        for (uint8 a = ADD; a <= TRANSFER; ++a) {
            uint256 snap = vm.snapshotState();
            Call memory c = _defaultCall(a);
            Call memory onTwin = _clone(c);
            onTwin.boardId = twin;
            bytes memory twinSig = _signed(onTwin);

            _assertRefused(c, twinSig, _badSignature(chair));
            (bool ok,) = _try(onTwin, twinSig);
            assertTrue(ok, "the signature is good on the board it was made for");
            vm.revertToState(snap);
        }
    }

    function test_EveryWrite_RefusesASignatureMadeForAnotherActionWithTheSameParams() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            uint256 boardId = a == CREATE ? 0 : c.boardId;
            for (uint8 other = CREATE; other <= TRANSFER; ++other) {
                if (other == a) continue;
                bytes memory m = _rawMessage(
                    block.chainid, address(registry), other, boardId, _paramsHash(c), _nonce(c), c.deadline
                );
                _assertRefused(c, _sign(chair, m), _badSignature(chair));
            }
        }
    }

    function test_EveryWrite_RefusesASignatureByAnotherRegisteredKey() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            bytes memory strangerSig = _sign(stranger, _messageOf(c, _nonce(c)));
            _assertRefused(c, strangerSig, _badSignature(chair));
        }
    }

    function test_EveryWrite_RefusesAnEmptySignature() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            _assertRefused(_defaultCall(a), "", _badSignature(chair));
        }
    }

    function test_EveryWrite_RefusesASignatureThatIsNot4627BytesEvenIfTheVerifierWouldAccept() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            bytes memory short = new bytes(4626);
            verifier.accept(_keyOf(chair), short, _messageOf(c, _nonce(c)));
            _assertRefused(c, short, _badSignature(chair));
        }
    }

    function test_EveryWrite_RefusesAnUnsignedMessage() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            _assertRefused(c, _sigFor(chair, _messageOf(c, _nonce(c))), _badSignature(chair));
        }
    }

    function test_EveryWrite_RefusesAnExpiredDeadline() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            c.deadline = T0 - 1;
            _assertRefused(c, abi.encodeWithSelector(BoardRegistry.DeadlineExpired.selector, T0 - 1, uint256(T0)));
        }
    }

    function test_EveryWrite_RefusesADeadlineMoreThanAnHourAhead() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            c.deadline = T0 + 3601;
            _assertRefused(
                c, abi.encodeWithSelector(BoardRegistry.DeadlineTooFar.selector, T0 + 3601, uint256(T0) + 3600)
            );
        }
    }

    function test_EveryWrite_AcceptsADeadlineOfNowAndOfExactlyAnHourAhead() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            uint256 snap = vm.snapshotState();
            Call memory c = _defaultCall(a);
            c.deadline = T0;
            _submit(c);
            vm.revertToState(snap);

            c.deadline = T0 + 3600;
            _submit(c);
            vm.revertToState(snap);
        }
    }

    function test_EveryWrite_RefusesAChangedDeadline() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            bytes memory sig = _signed(c);
            c.deadline += 1;
            _assertRefused(c, sig, _badSignature(chair));
        }
    }

    function test_EveryWrite_RefusesAnyChangedParameter() public {
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            bytes memory sig = _signed(c);
            Call[] memory changed = _mutations(c);
            assertGt(changed.length, 0);
            for (uint256 i; i < changed.length; ++i) {
                _assertRefused(changed[i], sig, _badSignature(_signer(changed[i])));
            }
        }
    }

    function test_EveryWrite_RefusesASignatureMadeForAnotherRegistryOrChain() public {
        BoardRegistry redeployed = new BoardRegistry();
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            uint256 boardId = a == CREATE ? 0 : c.boardId;
            bytes memory otherRegistry =
                _rawMessage(block.chainid, address(redeployed), a, boardId, _paramsHash(c), _nonce(c), c.deadline);
            _assertRefused(c, _sign(chair, otherRegistry), _badSignature(chair));
            bytes memory otherChain =
                _rawMessage(block.chainid + 1, address(registry), a, boardId, _paramsHash(c), _nonce(c), c.deadline);
            _assertRefused(c, _sign(chair, otherChain), _badSignature(chair));
        }
    }

    function test_EveryWrite_FollowsTheChairsCurrentKey() public {
        bytes memory newKey = new bytes(2592);
        newKey[0] = 0x42;
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            uint256 snap = vm.snapshotState();
            Call memory c = _defaultCall(a);
            bytes memory m = _messageOf(c, _nonce(c));
            bytes memory oldKeySig = _sign(chair, m);
            status.setKey(chair, true, 1, newKey, true);
            _assertRefused(c, oldKeySig, _badSignature(chair));

            bytes memory newKeySig = _sigFor(stranger, m);
            verifier.accept(newKey, newKeySig, m);
            _submit(c, newKeySig);
            vm.revertToState(snap);
        }
    }

    function test_EveryBoardWrite_RefusesAnUnknownBoard() public {
        for (uint8 a = ADD; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            c.boardId = 0;
            _assertRefused(c, _err(BoardRegistry.UnknownBoard.selector, uint256(0)));
            c.boardId = 3;
            _assertRefused(c, _err(BoardRegistry.UnknownBoard.selector, uint256(3)));
        }
    }

    function test_EnvelopeWrites_RefuseAZeroEnvelopeHash() public {
        for (uint8 a = CREATE; a <= ROTATE; ++a) {
            Call memory c = _defaultCall(a);
            c.hashA = bytes32(0);
            _assertRefused(c, _err(BoardRegistry.ZeroHash.selector));
        }
    }

    function test_EnvelopeWrites_RefuseAnEnvelopeSizeOf0OrAboveTheCap() public {
        for (uint8 a = CREATE; a <= ROTATE; ++a) {
            Call memory c = _defaultCall(a);
            c.envelopeSize = 0;
            _assertRefused(c, abi.encodeWithSelector(BoardRegistry.BadEnvelopeSize.selector, uint32(0)));
            c.envelopeSize = 110_001;
            _assertRefused(c, abi.encodeWithSelector(BoardRegistry.BadEnvelopeSize.selector, uint32(110_001)));
        }
    }

    function test_EnvelopeWrites_AcceptTheLargestEnvelope() public {
        for (uint8 a = CREATE; a <= ROTATE; ++a) {
            uint256 snap = vm.snapshotState();
            Call memory c = _defaultCall(a);
            c.envelopeSize = 110_000;
            _submit(c);
            vm.revertToState(snap);
        }
    }

    function test_EveryWrite_RefusesAChairWithNoKey() public {
        status.setKey(chair, false, 0, "", false);
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            _assertRefused(_defaultCall(a), _err(BoardRegistry.NoPqcKey.selector, chair));
        }
    }

    function test_EveryWrite_RefusesAChairWhoseKeyIsNotMlDsa87() public {
        status.setKey(chair, true, 2, _keyOf(chair), true);
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            _assertRefused(
                _defaultCall(a), abi.encodeWithSelector(BoardRegistry.WrongAlgorithm.selector, chair, uint8(2))
            );
        }
    }

    function test_EveryWrite_RefusesAChairWithoutProofOfPossession() public {
        status.setKey(chair, true, 1, _keyOf(chair), false);
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            _assertRefused(_defaultCall(a), _err(BoardRegistry.PossessionNotProven.selector, chair));
        }
    }

    function test_EveryWrite_RefusesAChairWhoseKeyIsNot2592Bytes() public {
        status.setKey(chair, true, 1, new bytes(1312), true);
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            _assertRefused(
                _defaultCall(a), abi.encodeWithSelector(BoardRegistry.BadKeyLength.selector, chair, uint256(1312))
            );
        }
    }

    function test_EveryWrite_RefusesValue() public {
        vm.deal(address(this), 1 ether);
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            Call memory c = _defaultCall(a);
            (bool ok,) = address(registry).call{value: 1}(_data(c, _signed(c)));
            assertFalse(ok, _name(a));
        }
        (bool plain,) = address(registry).call{value: 1}("");
        assertFalse(plain);
        (bool unknown,) = address(registry).call(hex"deadbeef");
        assertFalse(unknown);
        assertEq(address(registry).balance, 0);
    }

    // Message, params and views

    function test_DomainTag_IsTheSpecValueAndCannotBeginAReservedPrefix() public view {
        assertEq(registry.DOMAIN_TAG(), SPEC_TAG);
        assertEq(SPEC_TAG, keccak256("ava.board.v1"));
        assertEq(bytes1(SPEC_TAG), bytes1(0x20));
        assertNotEq(bytes1(SPEC_TAG), bytes1("q"));
    }

    function test_ActionMessage_IsTheSpecEncodingOf256Bytes() public view {
        bytes32 paramsHash = keccak256("params");
        bytes memory m = registry.actionMessage(ADD, 7, paramsHash, 3, 1_795_000_000);
        assertEq(m.length, 256);
        assertEq(m[0], bytes1(0x20));
        assertEq(
            m,
            abi.encode(
                SPEC_TAG,
                block.chainid,
                address(registry),
                uint256(2),
                uint256(7),
                paramsHash,
                uint256(3),
                uint256(1_795_000_000)
            )
        );
    }

    function test_ActionMessage_ChangesWithChainIdAndRegistry() public {
        bytes memory before = registry.actionMessage(POST, 1, bytes32(0), 0, DEADLINE);
        BoardRegistry other = new BoardRegistry();
        assertNotEq(keccak256(other.actionMessage(POST, 1, bytes32(0), 0, DEADLINE)), keccak256(before));
        vm.chainId(block.chainid + 1);
        assertNotEq(keccak256(registry.actionMessage(POST, 1, bytes32(0), 0, DEADLINE)), keccak256(before));
    }

    function test_Params_MatchTheSpecEncoding() public view {
        bytes32 h = keccak256("h");
        bytes32 h2 = keccak256("h2");
        assertEq(registry.paramsCreate(chair, h2, h, 9), keccak256(abi.encode(chair, h2, h, uint32(9))));
        assertEq(
            registry.paramsAdd(bob, ROTATE_MODE, h, 9, 4),
            keccak256(abi.encode(bob, ROTATE_MODE, h, uint32(9), uint64(4)))
        );
        assertEq(registry.paramsRemove(bob, h, 9, 4), keccak256(abi.encode(bob, h, uint32(9), uint64(4))));
        assertEq(registry.paramsRotate(h, 9, 4), keccak256(abi.encode(h, uint32(9), uint64(4))));
        assertEq(registry.paramsPost(h, h2, 9, 4), keccak256(abi.encode(h, h2, uint64(9), uint64(4))));
        assertEq(registry.paramsTransfer(bob), keccak256(abi.encode(bob)));
        assertNotEq(registry.paramsAdd(bob, SEAL_CURRENT, h, 9, 4), registry.paramsAdd(bob, ROTATE_MODE, h, 9, 4));
    }

    function test_Constants_MatchTheSpec() public view {
        assertEq(
            abi.encode(
                registry.CREATE(),
                registry.ADD(),
                registry.REMOVE(),
                registry.ROTATE(),
                registry.POST(),
                registry.TRANSFER(),
                registry.MODE_SEAL_CURRENT(),
                registry.MODE_ROTATE()
            ),
            abi.encode(1, 2, 3, 4, 5, 6, 0, 1)
        );
        assertEq(registry.MAX_MEMBERS(), 64);
        assertEq(registry.MAX_ENVELOPE_SIZE(), 110_000);
        assertGe(registry.MAX_ENVELOPE_SIZE(), 56 + 1632 * registry.MAX_MEMBERS() + 64);
        assertEq(registry.MAX_CIPHER_SIZE(), 26_214_400);
        assertEq(registry.MAX_DEADLINE_AHEAD(), 3600);
    }

    function test_Views_TreatUnknownBoardsAsUnknown() public {
        for (uint256 id; id <= 3; id += 3) {
            assertFalse(registry.exists(id));
            assertFalse(registry.isMember(id, chair));
            vm.expectRevert(_err(BoardRegistry.UnknownBoard.selector, id));
            registry.getBoard(id);
            vm.expectRevert(_err(BoardRegistry.UnknownBoard.selector, id));
            registry.getMembers(id);
            vm.expectRevert(_err(BoardRegistry.UnknownBoard.selector, id));
            registry.getGrants(id, 0);
            vm.expectRevert(_err(BoardRegistry.UnknownBoard.selector, id));
            registry.getDocument(id, 0);
        }
        assertFalse(registry.isMember(board, address(0)));
    }

    function test_GetGrants_IsEmptyForAnEpochTheBoardHasNotReached() public view {
        assertEq(registry.getGrants(board, 1).length, 0);
        assertEq(registry.getGrants(board, type(uint64).max).length, 0);
    }

    // Precompile failures: every write fails closed

    function _assertStatusFailureRefusesEveryWrite(MockPqcStatus.Answer answer, bool removeCode) internal {
        bytes memory expected = _err(BoardRegistry.PrecompileUnavailable.selector, PQC_STATUS);
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            uint256 snap = vm.snapshotState();
            Call memory c = _defaultCall(a);
            bytes memory sig = _signed(c);
            if (removeCode) vm.etch(PQC_STATUS, "");
            else status.setAnswer(answer);
            _assertRefused(c, sig, expected);
            vm.revertToState(snap);
        }
    }

    function _assertVerifyFailureRefusesEveryWrite(MockPqcVerify.Answer answer, bool removeCode) internal {
        bytes memory expected = _err(BoardRegistry.PrecompileUnavailable.selector, PQC_VERIFY);
        for (uint8 a = CREATE; a <= TRANSFER; ++a) {
            uint256 snap = vm.snapshotState();
            Call memory c = _defaultCall(a);
            bytes memory sig = _signed(c);
            if (removeCode) vm.etch(PQC_VERIFY, "");
            else verifier.setAnswer(answer);
            _assertRefused(c, sig, expected);
            vm.revertToState(snap);
        }
    }

    function test_EveryWrite_RefusesEmptyDataFromKeyStatus() public {
        _assertStatusFailureRefusesEveryWrite(MockPqcStatus.Answer.Empty, false);
    }

    function test_EveryWrite_RefusesShortDataFromKeyStatus() public {
        _assertStatusFailureRefusesEveryWrite(MockPqcStatus.Answer.Short, false);
    }

    function test_EveryWrite_RefusesWhenKeyStatusReverts() public {
        _assertStatusFailureRefusesEveryWrite(MockPqcStatus.Answer.Reverts, false);
    }

    function test_EveryWrite_RefusesWhenKeyStatusHasNoCode() public {
        _assertStatusFailureRefusesEveryWrite(MockPqcStatus.Answer.Normal, true);
    }

    function test_EveryWrite_RefusesEmptyDataFromVerify() public {
        _assertVerifyFailureRefusesEveryWrite(MockPqcVerify.Answer.Empty, false);
    }

    function test_EveryWrite_RefusesShortDataFromVerify() public {
        _assertVerifyFailureRefusesEveryWrite(MockPqcVerify.Answer.Short, false);
    }

    function test_EveryWrite_RefusesWhenVerifyReverts() public {
        _assertVerifyFailureRefusesEveryWrite(MockPqcVerify.Answer.Reverts, false);
    }

    function test_EveryWrite_RefusesWhenVerifyAnswerIsNotABool() public {
        _assertVerifyFailureRefusesEveryWrite(MockPqcVerify.Answer.NotABool, false);
    }

    function test_EveryWrite_RefusesWhenVerifyHasNoCode() public {
        _assertVerifyFailureRefusesEveryWrite(MockPqcVerify.Answer.Normal, true);
    }
}
