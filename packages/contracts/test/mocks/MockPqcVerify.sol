// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// @notice Stands in for QoreChain's pqcVerify precompile at 0x...0a01 in unit tests. It accepts
/// only the exact (pubkey, signature, message) triples a test registers, the way a real verifier
/// accepts only what was really signed, and answers false for everything else.
contract MockPqcVerify {
    enum Answer {
        Normal,
        Empty,
        Short,
        Reverts,
        NotABool
    }

    Answer public answer;
    mapping(bytes32 triple => bool ok) internal accepted;

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
