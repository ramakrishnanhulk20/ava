// Does not cover: signatures or any write (BoardRegistry.t.sol and BoardRegistryRealSig.t.sol do), or the guest challenge vector, which the bot builds and this contract never sees.
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {BoardRegistry} from "../src/BoardRegistry.sol";
import {PqcTestKit} from "./helpers/PqcTestKit.sol";

/// Proves the contract builds exactly the bytes packages/core's TypeScript library builds, using the
/// vector file that library writes (threat model C4). The registry runs at the vectors' address and
/// chain id, so address(this) and block.chainid inside the message match the file.
contract BoardRegistryVectorsTest is PqcTestKit {
    string internal constant VECTORS = "../core/test-vectors/actions.json";
    // The vector file names these two; they are repeated here so a changed file cannot move them silently.
    address internal constant VECTOR_REGISTRY = 0x00000000000000000000000000000000000A0A0A;
    uint256 internal constant VECTOR_CHAIN_ID = 9800;

    string internal json;
    BoardRegistry internal registry;

    function setUp() public {
        json = vm.readFile(VECTORS);
        registry = BoardRegistry(vm.parseJsonAddress(json, ".registry"));
        vm.etch(address(registry), type(BoardRegistry).runtimeCode);
        vm.chainId(vm.parseJsonUint(json, ".chainId"));
    }

    function _key(uint256 index, string memory field) internal pure returns (string memory) {
        return string.concat(".vectors[", vm.toString(index), "].", field);
    }

    function _param(uint256 index, string memory field) internal pure returns (string memory) {
        return _key(index, string.concat("params.", field));
    }

    function _u64(uint256 index, string memory field) internal view returns (uint64) {
        return SafeCast.toUint64(vm.parseJsonUint(json, _param(index, field)));
    }

    function _u32(uint256 index, string memory field) internal view returns (uint32) {
        return SafeCast.toUint32(vm.parseJsonUint(json, _param(index, field)));
    }

    // Checks the vector's name and action code, that the contract's paramsHash is the vector's, and
    // that the contract's message over it is the vector's message byte for byte.
    function _assertVector(uint256 index, string memory name, uint8 action, bytes32 paramsHash) internal view {
        assertEq(vm.parseJsonString(json, _key(index, "name")), name);
        assertEq(vm.parseJsonUint(json, _key(index, "action")), action, name);
        assertEq(paramsHash, vm.parseJsonBytes32(json, _key(index, "paramsHash")), name);

        bytes memory message = registry.actionMessage(
            action,
            vm.parseJsonUint(json, _key(index, "boardId")),
            paramsHash,
            SafeCast.toUint64(vm.parseJsonUint(json, _key(index, "nonce"))),
            SafeCast.toUint64(vm.parseJsonUint(json, _key(index, "deadline")))
        );
        bytes memory expected = vm.parseJsonBytes(json, _key(index, "message"));
        assertEq(expected.length, 256, name);
        assertEq(message, expected, name);
    }

    function test_Vectors_RunAtTheVectorRegistryAndChainWithTheSpecTag() public view {
        assertEq(address(registry), VECTOR_REGISTRY);
        assertEq(block.chainid, VECTOR_CHAIN_ID);
        assertEq(registry.DOMAIN_TAG(), vm.parseJsonBytes32(json, ".domainTag"));
        assertTrue(vm.keyExistsJson(json, ".vectors[5]"));
        assertFalse(vm.keyExistsJson(json, ".vectors[6]"), "a seventh vector has no test here");
    }

    function test_Vectors_Create() public view {
        bytes32 h = registry.paramsCreate(
            vm.parseJsonAddress(json, _param(0, "chair")),
            vm.parseJsonBytes32(json, _param(0, "boardRef")),
            vm.parseJsonBytes32(json, _param(0, "envelopeHash")),
            _u32(0, "envelopeSize")
        );
        _assertVector(0, "CREATE", registry.CREATE(), h);
    }

    function test_Vectors_Add() public view {
        bytes32 h = registry.paramsAdd(
            vm.parseJsonAddress(json, _param(1, "member")),
            SafeCast.toUint8(vm.parseJsonUint(json, _param(1, "mode"))),
            vm.parseJsonBytes32(json, _param(1, "envelopeHash")),
            _u32(1, "envelopeSize"),
            _u64(1, "epochAfter")
        );
        _assertVector(1, "ADD", registry.ADD(), h);
    }

    function test_Vectors_Remove() public view {
        bytes32 h = registry.paramsRemove(
            vm.parseJsonAddress(json, _param(2, "member")),
            vm.parseJsonBytes32(json, _param(2, "envelopeHash")),
            _u32(2, "envelopeSize"),
            _u64(2, "epochAfter")
        );
        _assertVector(2, "REMOVE", registry.REMOVE(), h);
    }

    function test_Vectors_Rotate() public view {
        bytes32 h = registry.paramsRotate(
            vm.parseJsonBytes32(json, _param(3, "envelopeHash")), _u32(3, "envelopeSize"), _u64(3, "epochAfter")
        );
        _assertVector(3, "ROTATE", registry.ROTATE(), h);
    }

    function test_Vectors_Post() public view {
        bytes32 h = registry.paramsPost(
            vm.parseJsonBytes32(json, _param(4, "docRef")),
            vm.parseJsonBytes32(json, _param(4, "cipherHash")),
            _u64(4, "cipherSize"),
            _u64(4, "epoch")
        );
        _assertVector(4, "POST", registry.POST(), h);
    }

    function test_Vectors_Transfer() public view {
        bytes32 h = registry.paramsTransfer(vm.parseJsonAddress(json, _param(5, "newChair")));
        _assertVector(5, "TRANSFER", registry.TRANSFER(), h);
    }
}
