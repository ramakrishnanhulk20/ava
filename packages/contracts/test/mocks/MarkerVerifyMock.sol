// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// @notice Stands in for QoreChain's pqcVerify precompile at 0x...0a01 in the fuzz and invariant
/// suites. It models ML-DSA-87 as a function of (key, message) that only the key's holder computes:
/// a signature is good exactly when it is 4,627 bytes, its first 32 bytes are
/// keccak256(abi.encode(pubkey, message)), and every byte after those is 0x5a. A test can sign any
/// message for a key it holds, and what it signs for one key or one message verifies for no other.
/// @dev Unlike MockPqcVerify it needs nothing registered up front, so a handler can sign thousands of
/// random actions. PqcTestKit._markerSignature builds the signatures.
contract MarkerVerifyMock {
    uint256 internal constant SIGNATURE_BYTES = 4627;
    uint256 internal constant HEAD_BYTES = 32;
    bytes32 internal constant FILL = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a;

    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        pure
        returns (bool)
    {
        if (signature.length != SIGNATURE_BYTES) return false;
        if (bytes32(signature[:HEAD_BYTES]) != keccak256(abi.encode(pubkey, message))) return false;
        for (uint256 i = HEAD_BYTES; i + 32 <= SIGNATURE_BYTES; i += 32) {
            if (bytes32(signature[i:i + 32]) != FILL) return false;
        }
        // 4,595 fill bytes are not a whole number of words, so the last word overlaps the one before it.
        return bytes32(signature[SIGNATURE_BYTES - 32:]) == FILL;
    }
}
