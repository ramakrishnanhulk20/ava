// The real ML-DSA-87 verification happens inside test/ffi/sign.mjs and, on chain, in QoreChain's pqcVerify precompile, not in the mock: the mock only accepts the one triple sign.mjs signed and verified.
// Does not cover: rotateEpoch (same signature gate, covered with stand-in signatures in BoardRegistry.t.sol), the live precompiles, or hedged signatures. Run with FOUNDRY_PROFILE=realsig forge test.
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {Vm} from "forge-std/Vm.sol";
import {BoardRegistry} from "../src/BoardRegistry.sol";
import {PqcTestKit} from "./helpers/PqcTestKit.sol";

contract BoardRegistryRealSigTest is PqcTestKit {
    uint64 internal constant T0 = 1_794_787_200;
    uint64 internal constant DEADLINE = T0 + 600;
    uint32 internal constant ENVELOPE_SIZE = 4_985;
    uint64 internal constant CIPHER_SIZE = 40_000;
    uint8 internal constant SEAL_CURRENT = 0;
    // Test fixtures only. Each seed derives one ML-DSA-87 key pair inside sign.mjs.
    bytes32 internal constant CHAIR_SEED = keccak256("ava realsig chair seed");
    bytes32 internal constant BOB_SEED = keccak256("ava realsig bob seed");

    BoardRegistry internal registry;
    address internal chair = makeAddr("chair");
    address internal bob = makeAddr("bob");

    function setUp() public {
        vm.warp(T0);
        _etchPqcMocks();
        registry = new BoardRegistry();
        (bytes memory bobKey,) = _realSign(BOB_SEED, "ava realsig: bob's key");
        _registerKey(bob, bobKey);
    }

    // Runs sign.mjs and refuses anything but a clean exit with a real-sized key and signature.
    function _realSign(bytes32 seed, bytes memory message) internal returns (bytes memory pubkey, bytes memory sig) {
        string[] memory cmd = new string[](4);
        cmd[0] = "node";
        cmd[1] = "test/ffi/sign.mjs";
        cmd[2] = vm.toString(seed);
        cmd[3] = vm.toString(message);
        Vm.FfiResult memory result = vm.tryFfi(cmd);
        assertEq(result.exitCode, 0, string(result.stderr));
        (pubkey, sig) = abi.decode(result.stdout, (bytes, bytes));
        assertEq(pubkey.length, PQC_ML_DSA_87_PUBKEY_BYTES, "a real ML-DSA-87 public key is 2,592 bytes");
        assertEq(sig.length, PQC_ML_DSA_87_SIGNATURE_BYTES, "a real ML-DSA-87 signature is 4,627 bytes");
    }

    // Signs with the chair's real key, then registers that key for the chair and exactly that
    // (pubkey, signature, message) triple, so the mock knows nothing else.
    function _chairSigns(bytes memory message) internal returns (bytes memory sig) {
        bytes memory pubkey;
        (pubkey, sig) = _realSign(CHAIR_SEED, message);
        _registerKey(chair, pubkey);
        _registerTriple(pubkey, sig, message);
    }

    function _flip(bytes32 value) internal pure returns (bytes32) {
        return value ^ bytes32(bytes1(0xff));
    }

    function _badSignature() internal view returns (bytes memory) {
        return abi.encodeWithSelector(BoardRegistry.BadSignature.selector, chair);
    }

    function _createMessage(bytes32 boardRef, bytes32 envelopeHash) internal view returns (bytes memory) {
        bytes32 paramsHash = registry.paramsCreate(chair, boardRef, envelopeHash, ENVELOPE_SIZE);
        return registry.actionMessage(registry.CREATE(), 0, paramsHash, registry.createNonces(chair), DEADLINE);
    }

    function _addMessage(uint256 boardId, bytes32 envelopeHash) internal view returns (bytes memory) {
        bytes32 paramsHash = registry.paramsAdd(bob, SEAL_CURRENT, envelopeHash, ENVELOPE_SIZE, 0);
        return registry.actionMessage(registry.ADD(), boardId, paramsHash, registry.getBoard(boardId).nonce, DEADLINE);
    }

    function _newBoard() internal returns (uint256 boardId) {
        bytes32 boardRef = keccak256("realsig board ref");
        bytes32 envelopeHash = sha256("realsig epoch 0 envelope");
        bytes memory sig = _chairSigns(_createMessage(boardRef, envelopeHash));
        boardId = registry.createBoard(chair, boardRef, envelopeHash, ENVELOPE_SIZE, DEADLINE, sig);
    }

    function _newBoardWithBob() internal returns (uint256 boardId) {
        boardId = _newBoard();
        bytes32 envelopeHash = sha256("realsig bob envelope");
        bytes memory sig = _chairSigns(_addMessage(boardId, envelopeHash));
        registry.addMember(boardId, bob, SEAL_CURRENT, envelopeHash, ENVELOPE_SIZE, 0, DEADLINE, sig);
    }

    function test_RealSig_CreateBoard() public {
        bytes32 boardRef = keccak256("realsig board ref");
        bytes32 envelopeHash = sha256("realsig epoch 0 envelope");
        bytes memory sig = _chairSigns(_createMessage(boardRef, envelopeHash));

        uint256 snap = vm.snapshotState();
        assertEq(registry.createBoard(chair, boardRef, envelopeHash, ENVELOPE_SIZE, DEADLINE, sig), 1);
        assertEq(registry.getBoard(1).chair, chair);
        assertEq(registry.createNonces(chair), 1);
        vm.revertToState(snap);

        vm.expectRevert(_badSignature());
        registry.createBoard(chair, _flip(boardRef), envelopeHash, ENVELOPE_SIZE, DEADLINE, sig);
    }

    function test_RealSig_AddMember() public {
        uint256 boardId = _newBoard();
        bytes32 envelopeHash = sha256("realsig bob envelope");
        bytes memory sig = _chairSigns(_addMessage(boardId, envelopeHash));

        uint256 snap = vm.snapshotState();
        registry.addMember(boardId, bob, SEAL_CURRENT, envelopeHash, ENVELOPE_SIZE, 0, DEADLINE, sig);
        assertTrue(registry.isMember(boardId, bob));
        assertEq(registry.getBoard(boardId).memberCount, 2);
        vm.revertToState(snap);

        vm.expectRevert(_badSignature());
        registry.addMember(boardId, bob, SEAL_CURRENT, _flip(envelopeHash), ENVELOPE_SIZE, 0, DEADLINE, sig);
    }

    function test_RealSig_RemoveMember() public {
        uint256 boardId = _newBoardWithBob();
        bytes32 envelopeHash = sha256("realsig epoch 1 envelope");
        bytes32 paramsHash = registry.paramsRemove(bob, envelopeHash, ENVELOPE_SIZE, 1);
        bytes memory sig = _chairSigns(
            registry.actionMessage(registry.REMOVE(), boardId, paramsHash, registry.getBoard(boardId).nonce, DEADLINE)
        );

        uint256 snap = vm.snapshotState();
        registry.removeMember(boardId, bob, envelopeHash, ENVELOPE_SIZE, 1, DEADLINE, sig);
        assertFalse(registry.isMember(boardId, bob));
        assertEq(registry.getBoard(boardId).epoch, 1);
        vm.revertToState(snap);

        vm.expectRevert(_badSignature());
        registry.removeMember(boardId, bob, envelopeHash, ENVELOPE_SIZE ^ 0xff, 1, DEADLINE, sig);
    }

    function test_RealSig_PostDocument() public {
        uint256 boardId = _newBoard();
        bytes32 docRef = keccak256("realsig doc ref");
        bytes32 cipherHash = sha256("realsig ciphertext");
        bytes32 paramsHash = registry.paramsPost(docRef, cipherHash, CIPHER_SIZE, 0);
        bytes memory sig = _chairSigns(
            registry.actionMessage(registry.POST(), boardId, paramsHash, registry.getBoard(boardId).nonce, DEADLINE)
        );

        uint256 snap = vm.snapshotState();
        assertEq(registry.postDocument(boardId, docRef, cipherHash, CIPHER_SIZE, 0, DEADLINE, sig), 0);
        assertEq(registry.getDocument(boardId, 0).cipherHash, cipherHash);
        vm.revertToState(snap);

        vm.expectRevert(_badSignature());
        registry.postDocument(boardId, docRef, _flip(cipherHash), CIPHER_SIZE, 0, DEADLINE, sig);
    }

    function test_RealSig_TransferChair() public {
        uint256 boardId = _newBoardWithBob();
        bytes32 paramsHash = registry.paramsTransfer(bob);
        bytes memory sig = _chairSigns(
            registry.actionMessage(registry.TRANSFER(), boardId, paramsHash, registry.getBoard(boardId).nonce, DEADLINE)
        );

        uint256 snap = vm.snapshotState();
        registry.transferChair(boardId, bob, DEADLINE, sig);
        assertEq(registry.getBoard(boardId).chair, bob);
        vm.revertToState(snap);

        // The deadline is part of the signed message too; one flipped byte still lands inside the window.
        vm.expectRevert(_badSignature());
        registry.transferChair(boardId, bob, DEADLINE ^ 0xff, sig);
    }
}
