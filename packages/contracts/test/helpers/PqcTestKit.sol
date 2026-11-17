// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";
import {MockPqcStatus} from "../mocks/MockPqcStatus.sol";
import {MockPqcVerify} from "../mocks/MockPqcVerify.sol";
import {MarkerVerifyMock} from "../mocks/MarkerVerifyMock.sol";

/// @notice Foundry wiring for any contract that calls QoreChain's post-quantum precompiles. It puts
/// a stand-in at each precompile address and tells them which keys exist and which signatures are
/// good. To reuse it, copy this file and the three mocks in test/mocks, then make your test contract
/// inherit PqcTestKit and call _etchPqcMocks() or _etchMarkerPqcMocks() in setUp.
/// @dev The verify stand-in does no ML-DSA maths. It accepts exactly the (pubkey, signature,
/// message) triples registered with _registerTriple and answers false for everything else, so a
/// test proves the contract asked about the right bytes. Pair it with real signatures (see
/// BoardRegistryRealSig.t.sol) to prove those bytes are what a real ML-DSA-87 key signs.
abstract contract PqcTestKit is Test {
    address internal constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
    address internal constant PQC_STATUS = 0x0000000000000000000000000000000000000a02;
    uint8 internal constant PQC_ML_DSA_87 = 1;
    uint256 internal constant PQC_ML_DSA_87_PUBKEY_BYTES = 2592;
    uint256 internal constant PQC_ML_DSA_87_SIGNATURE_BYTES = 4627;

    /// @notice Puts the two stand-ins at 0x...0a01 and 0x...0a02. Call it before registering anything.
    function _etchPqcMocks() internal {
        vm.etch(PQC_STATUS, type(MockPqcStatus).runtimeCode);
        vm.etch(PQC_VERIFY, type(MockPqcVerify).runtimeCode);
    }

    /// @notice Makes pqcKeyStatus(account) answer: registered, ML-DSA-87, `pubkey`, possession proven.
    /// @param account The account the key belongs to.
    /// @param pubkey The public key to report for it.
    function _registerKey(address account, bytes memory pubkey) internal {
        MockPqcStatus(PQC_STATUS).setKey(account, true, PQC_ML_DSA_87, pubkey, true);
    }

    /// @notice Makes pqcVerify answer true for exactly this triple. Any other triple stays false.
    /// @param pubkey The public key.
    /// @param signature The signature.
    /// @param message The exact signed bytes.
    function _registerTriple(bytes memory pubkey, bytes memory signature, bytes memory message) internal {
        MockPqcVerify(PQC_VERIFY).accept(pubkey, signature, message);
    }

    /// @notice Puts the key-status stand-in at 0x...0a02 and MarkerVerifyMock at 0x...0a01, for suites
    /// that sign too many messages to register each one. Call it before registering anything.
    function _etchMarkerPqcMocks() internal {
        vm.etch(PQC_STATUS, type(MockPqcStatus).runtimeCode);
        vm.etch(PQC_VERIFY, type(MarkerVerifyMock).runtimeCode);
    }

    /// @notice The one signature MarkerVerifyMock accepts for `pubkey` over `message`.
    /// @param pubkey The signer's public key.
    /// @param message The exact signed bytes.
    /// @return The 4,627-byte marker signature.
    function _markerSignature(bytes memory pubkey, bytes memory message) internal pure returns (bytes memory) {
        return _markerSignature(pubkey, message, PQC_ML_DSA_87_SIGNATURE_BYTES);
    }

    /// @notice The marker signature's bytes cut or stretched to `length`: the marker head (or as much
    /// of it as fits), then 0x5a. At any length but 4,627 it is the right signature at the wrong size.
    /// @param pubkey The signer's public key.
    /// @param message The exact signed bytes.
    /// @param length The length to build.
    /// @return sig The bytes.
    function _markerSignature(bytes memory pubkey, bytes memory message, uint256 length)
        internal
        pure
        returns (bytes memory sig)
    {
        bytes32 head = keccak256(abi.encode(pubkey, message));
        sig = new bytes(length);
        if (length < 32) {
            for (uint256 i; i < length; ++i) {
                sig[i] = head[i];
            }
            return sig;
        }
        // Whole words only inside the buffer: the last fill word is placed to end exactly at `length`,
        // and the head goes in last because that word can reach back over it.
        assembly ("memory-safe") {
            let data := add(sig, 32)
            let fill := 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
            for { let i := 32 } iszero(gt(add(i, 32), length)) { i := add(i, 32) } { mstore(add(data, i), fill) }
            mstore(add(data, sub(length, 32)), fill)
            mstore(data, head)
        }
    }
}
