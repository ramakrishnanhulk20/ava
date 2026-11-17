// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// @notice Stands in for QoreChain's pqcKeyStatus precompile at 0x...0a02 in unit tests. It is
/// etched at that address, so all of its state is set through calls, one key per account.
contract MockPqcStatus {
    enum Answer {
        Normal,
        Empty,
        Short,
        Reverts
    }

    struct Key {
        bool registered;
        uint8 algorithmId;
        bytes pubkey;
        bool possessionProven;
    }

    Answer public answer;
    mapping(address account => Key key) internal keys;

    function setAnswer(Answer a) external {
        answer = a;
    }

    function setKey(address account, bool registered, uint8 algorithmId, bytes calldata pubkey, bool possessionProven)
        external
    {
        keys[account] = Key(registered, algorithmId, pubkey, possessionProven);
    }

    function pqcKeyStatus(address account) external view returns (bool, uint8, bytes memory, bool) {
        Answer a = answer;
        if (a == Answer.Empty) {
            assembly {
                return(0, 0)
            }
        }
        if (a == Answer.Short) {
            // The four head words with no length word for the key: 128 bytes, one word short of
            // the smallest real answer.
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
