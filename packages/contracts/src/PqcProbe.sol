// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {IQorePQC} from "./interfaces/IQorePQC.sol";

/// @title PqcProbe
/// @author Ava
/// @notice Records a digest for a signer only when that signer's registered, possession-proven
/// ML-DSA-87 key signed it. The chain's pqcVerify precompile does the check, so the transaction
/// sender, and its classical key, grant nothing. Holds no value and has no owner.
contract PqcProbe {
    address internal constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
    address internal constant PQC_STATUS = 0x0000000000000000000000000000000000000a02;
    // The human tag starts with "a" and its hash with 0x9f, so no signed message can begin with
    // a QoreChain reserved prefix, all of which start with "q".
    bytes32 internal constant DOMAIN_TAG = keccak256("ava.probe.v1");

    uint8 private constant ML_DSA_87 = 1;
    uint256 private constant ML_DSA_87_PUBKEY_LENGTH = 2592;
    uint256 private constant ML_DSA_87_SIGNATURE_LENGTH = 4627;
    // Four ABI head words plus the length word of an empty key. The live precompile answers an
    // unregistered account with exactly this many bytes.
    uint256 private constant MIN_STATUS_RETURN_LENGTH = 160;

    /// @notice The next nonce each signer must sign. It starts at 0 and goes up by one per record.
    mapping(address signer => uint256 nonce) public nonces;

    /// @notice Emitted once per accepted signature.
    /// @param signer The account whose ML-DSA-87 key signed.
    /// @param digest The 32 bytes that were signed for.
    /// @param nonce The nonce the signature covered.
    event Recorded(address indexed signer, bytes32 indexed digest, uint256 nonce);

    /// @notice The signer has no post-quantum key on file.
    error NoPqcKey(address signer);
    /// @notice The signer's key is not ML-DSA-87.
    error WrongAlgorithm(address signer, uint8 algorithmId);
    /// @notice The signer's key was registered without a proof of possession.
    error PossessionNotProven(address signer);
    /// @notice The registered key is not 2,592 bytes.
    error BadKeyLength(address signer, uint256 length);
    /// @notice A precompile reverted, or answered with empty, short or malformed data.
    error PrecompileUnavailable(address precompile);
    /// @notice The signature does not verify for the message this contract builds.
    error BadSignature(address signer);

    /// @notice Records `digest` for `signer` if `signature` is the signer's ML-DSA-87 signature over
    /// `messageFor(signer, digest)`. Anyone may submit it; the signature is the only authority.
    /// @dev Reverts NoPqcKey, WrongAlgorithm, PossessionNotProven or BadKeyLength when the signer's
    /// key is not a possession-proven 2,592-byte ML-DSA-87 key; BadSignature when the signature is
    /// not 4,627 bytes or does not verify (a replay fails here, because the nonce has moved);
    /// PrecompileUnavailable when either precompile reverts or answers with empty or short data.
    /// Emits Recorded with the nonce that was signed, then moves the signer's nonce up by one.
    /// @param signer The account whose key signed.
    /// @param digest The 32 bytes to record.
    /// @param signature The 4,627-byte ML-DSA-87 signature.
    function record(address signer, bytes32 digest, bytes calldata signature) external {
        bytes memory pubkey = _provenKey(signer);
        if (signature.length != ML_DSA_87_SIGNATURE_LENGTH) revert BadSignature(signer);

        uint256 nonce = nonces[signer];
        if (!_verify(pubkey, signature, _message(signer, digest, nonce))) revert BadSignature(signer);

        nonces[signer] = nonce + 1;
        emit Recorded(signer, digest, nonce);
    }

    /// @notice The exact bytes `signer` must sign to record `digest` next.
    /// @dev abi.encode(DOMAIN_TAG, block.chainid, address(this), signer, digest, nonces[signer]):
    /// 192 bytes, fixed length, bound to this chain, this contract, the signer and the next nonce.
    /// @param signer The account that will sign.
    /// @param digest The 32 bytes to record.
    /// @return The message to sign with pure ML-DSA-87, empty context.
    function messageFor(address signer, bytes32 digest) public view returns (bytes memory) {
        return _message(signer, digest, nonces[signer]);
    }

    function _message(address signer, bytes32 digest, uint256 nonce) private view returns (bytes memory) {
        return abi.encode(DOMAIN_TAG, block.chainid, address(this), signer, digest, nonce);
    }

    // Low-level calls on purpose: an inactive precompile answers a call with success and empty
    // data, which a high-level call would not let us tell apart from a real answer.
    function _provenKey(address signer) private view returns (bytes memory pubkey) {
        (bool ok, bytes memory ret) = PQC_STATUS.staticcall(abi.encodeCall(IQorePQC.pqcKeyStatus, (signer)));
        if (!ok || ret.length < MIN_STATUS_RETURN_LENGTH) revert PrecompileUnavailable(PQC_STATUS);

        bool registered;
        uint8 algorithmId;
        bool possessionProven;
        (registered, algorithmId, pubkey, possessionProven) = abi.decode(ret, (bool, uint8, bytes, bool));

        if (!registered) revert NoPqcKey(signer);
        if (algorithmId != ML_DSA_87) revert WrongAlgorithm(signer, algorithmId);
        if (!possessionProven) revert PossessionNotProven(signer);
        if (pubkey.length != ML_DSA_87_PUBKEY_LENGTH) revert BadKeyLength(signer, pubkey.length);
    }

    function _verify(bytes memory pubkey, bytes calldata signature, bytes memory message) private view returns (bool) {
        (bool ok, bytes memory ret) =
            PQC_VERIFY.staticcall(abi.encodeCall(IQorePQC.pqcVerify, (pubkey, signature, message)));
        if (!ok || ret.length < 32) revert PrecompileUnavailable(PQC_VERIFY);

        // Anything other than a clean 0 or 1 is not an answer we can trust either way.
        uint256 answer = abi.decode(ret, (uint256));
        if (answer > 1) revert PrecompileUnavailable(PQC_VERIFY);
        return answer == 1;
    }
}
