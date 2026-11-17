// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// @title QoreChain post-quantum precompiles
/// @author QoreChain
/// @notice pqcVerify answers at 0x...0a01 and pqcKeyStatus at 0x...0a02 on the QoreChain testnet.
interface IQorePQC {
    /// @notice Checks a pure ML-DSA-87 signature (empty context, no prehash) over `message`.
    /// @param pubkey The 2,592-byte ML-DSA-87 public key.
    /// @param signature The signature to check.
    /// @param message The exact bytes that were signed.
    /// @return valid True only for a valid signature. Malformed input returns false.
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool valid);

    /// @notice Reads the post-quantum key registered for `account`.
    /// @param account The 20-byte account, the same bytes as its qor1 address.
    /// @return registered Whether a key is on file.
    /// @return algorithmId 1 for ML-DSA-87.
    /// @return pubkey The registered public key.
    /// @return possessionProven Whether the key's holder proved possession when it was registered.
    function pqcKeyStatus(address account)
        external
        view
        returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}
