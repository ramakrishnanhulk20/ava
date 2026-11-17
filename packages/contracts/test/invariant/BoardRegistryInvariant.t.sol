// Does not cover: real ML-DSA-87 maths (MarkerVerifyMock models it), events and precompile outages (BoardRegistry.t.sol), boards near the 64-member cap (the handler has 8 keyed actors; BoardRegistry.t.sol fills a board to 64), keys that change or lose their proof mid-run, or the exact deadline and size edges (BoardRegistryFuzz.t.sol).
// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {BoardRegistry} from "../../src/BoardRegistry.sol";
import {PqcTestKit} from "../helpers/PqcTestKit.sol";
import {Handler} from "./Handler.sol";

/// Ten properties of every board, checked after every call in thousands of random sequences of chair
/// moves and attacks (see Handler). Threat model C1, C2, C5, C6, C7, C8, C10 and C17.
contract BoardRegistryInvariantTest is PqcTestKit {
    uint64 internal constant T0 = 1_794_787_200;
    uint256 internal constant MAX_MEMBERS = 64;

    BoardRegistry internal registry;
    Handler internal handler;

    function setUp() public {
        vm.warp(T0);
        _etchMarkerPqcMocks();
        registry = new BoardRegistry();
        handler = new Handler(registry);

        bytes4[] memory moves = new bytes4[](11);
        moves[0] = Handler.create.selector;
        moves[1] = Handler.addSealCurrent.selector;
        moves[2] = Handler.addRotate.selector;
        moves[3] = Handler.remove.selector;
        moves[4] = Handler.rotate.selector;
        moves[5] = Handler.post.selector;
        moves[6] = Handler.transfer.selector;
        moves[7] = Handler.attackWrongSigner.selector;
        moves[8] = Handler.attackReplay.selector;
        moves[9] = Handler.attackCrossBoard.selector;
        moves[10] = Handler.attackStaleNonce.selector;
        targetContract(address(handler));
        targetSelector(FuzzSelector({addr: address(handler), selectors: moves}));
    }

    /// 1. C7: the chair is always a member of its board, and is the one the ghost expects.
    function invariant_01_TheChairIsAlwaysAMember() public view {
        for (uint256 id = 1; id <= handler.ghostBoardCount(); ++id) {
            address chair = registry.getBoard(id).chair;
            assertTrue(registry.isMember(id, chair), "the chair is not a member");
            assertEq(chair, handler.ghostBoard(id).chair, "the chair is not the one the ghost expects");
        }
    }

    /// 2. C7, C8: memberCount stays from 1 to 64 and matches the member list.
    function invariant_02_MemberCountStaysFrom1To64() public view {
        for (uint256 id = 1; id <= handler.ghostBoardCount(); ++id) {
            uint256 count = registry.getBoard(id).memberCount;
            assertGe(count, 1, "a board with no members");
            assertLe(count, MAX_MEMBERS, "a board over MAX_MEMBERS");
            assertEq(registry.getMembers(id).length, count, "memberCount differs from the member list");
        }
    }

    /// 3. C5, C17: the epoch never goes down, and moves by exactly one for each landed rotate, remove
    /// or rotating add on its board, and not at all for anything else.
    function invariant_03_TheEpochOnlyStepsUpByOneForAnEpochMove() public view {
        for (uint256 id = 1; id <= handler.ghostBoardCount(); ++id) {
            assertEq(registry.getBoard(id).epoch, handler.ghostBoard(id).epoch, "the epoch differs from the ghost");
        }
        assertEq(handler.epochStepViolations(), 0, "a call moved an epoch by something other than its one step");
    }

    /// 4. C2: each board's nonce is the number of its actions that landed, and each chair's creation
    /// nonce the number of boards it created.
    function invariant_04_TheNonceCountsTheActionsThatLanded() public view {
        for (uint256 id = 1; id <= handler.ghostBoardCount(); ++id) {
            assertEq(registry.getBoard(id).nonce, handler.ghostBoard(id).landed, "the nonce differs from the count");
        }
        for (uint256 i; i < handler.ACTOR_COUNT(); ++i) {
            address a = handler.actor(i);
            assertEq(registry.createNonces(a), handler.ghostCreateNonce(a), "a creation nonce differs from the count");
        }
    }

    /// 5. C5: every document carries the epoch its board had on chain when the post landed, never
    /// above the current one. Read from the chain, not the model, so it holds for posts the model
    /// would have refused too.
    function invariant_05_EveryDocumentKeepsTheEpochItWasPostedIn() public view {
        for (uint256 id = 1; id <= handler.ghostBoardCount(); ++id) {
            BoardRegistry.Board memory b = registry.getBoard(id);
            uint64[] memory posted = handler.epochsWhenPosted(id);
            assertEq(b.documentCount, posted.length, "a document that no landed post accounts for");
            for (uint256 d; d < posted.length; ++d) {
                uint64 epoch = registry.getDocument(id, d).epoch;
                assertEq(epoch, posted[d], "a document under another epoch than its board had");
                assertLe(epoch, b.epoch, "a document above the current epoch");
            }
        }
    }

    /// 6. C6: documents and grants are append-only. Every stored record equals the ghost copy taken
    /// when it landed, nothing is missing or extra, and no grant exists for an epoch not yet reached.
    function invariant_06_DocumentsAndGrantsAreAppendOnly() public view {
        for (uint256 id = 1; id <= handler.ghostBoardCount(); ++id) {
            BoardRegistry.Board memory b = registry.getBoard(id);
            BoardRegistry.Document[] memory docs = handler.ghostDocumentList(id);
            assertEq(b.documentCount, docs.length, "documentCount differs from the ghost");
            for (uint256 d; d < docs.length; ++d) {
                assertEq(abi.encode(registry.getDocument(id, d)), abi.encode(docs[d]), "a document changed");
            }
            uint64 top = b.epoch > handler.ghostBoard(id).epoch ? b.epoch : handler.ghostBoard(id).epoch;
            for (uint64 e; e <= top; ++e) {
                assertEq(
                    abi.encode(registry.getGrants(id, e)), abi.encode(handler.ghostGrantList(id, e)), "a grant list changed"
                );
            }
            assertEq(registry.getGrants(id, top + 1).length, 0, "a grant for an epoch not yet reached");
        }
    }

    /// 7. C7: isMember agrees with the ghost for every actor on every board, and the member list holds
    /// no one else.
    function invariant_07_IsMemberMatchesTheGhostForEveryActor() public view {
        for (uint256 id = 1; id <= handler.ghostBoardCount(); ++id) {
            for (uint256 i; i < handler.ACTOR_COUNT(); ++i) {
                address a = handler.actor(i);
                assertEq(registry.isMember(id, a), handler.isGhostMember(id, a), "isMember differs from the ghost");
            }
            address[] memory listed = registry.getMembers(id);
            for (uint256 m; m < listed.length; ++m) {
                assertTrue(handler.isGhostMember(id, listed[m]), "a listed member the ghost does not hold");
            }
            assertFalse(registry.isMember(id, address(0)), "the zero address is a member");
        }
    }

    /// 8. C7: boardIdOf(boardRef) finds each board, refs never change, and no two boards share one.
    function invariant_08_EveryBoardRefFindsItsOwnBoard() public view {
        uint256 count = registry.boardCount();
        assertEq(count, handler.ghostBoardCount(), "boardCount differs from the ghost");
        for (uint256 id = 1; id <= count; ++id) {
            bytes32 ref = registry.getBoard(id).boardRef;
            assertNotEq(ref, bytes32(0), "a zero boardRef");
            assertEq(ref, handler.ghostBoard(id).boardRef, "a boardRef changed");
            assertEq(registry.boardIdOf(ref), id, "boardIdOf points elsewhere");
            for (uint256 other = 1; other < id; ++other) {
                assertNotEq(ref, registry.getBoard(other).boardRef, "two boards share a boardRef");
            }
        }
        assertEq(registry.boardIdOf(bytes32(0)), 0, "the zero boardRef finds a board");
        assertFalse(registry.exists(count + 1), "a board past boardCount exists");
    }

    /// 9. C1, C2, C17: no attack move (a signer other than the chair, a replay, a signature naming
    /// another board, a used or future nonce) is accepted or changes anything a read can see.
    function invariant_09_NoAttackChangesAnything() public view {
        assertEq(handler.attacksLanded(), 0, "an attack landed");
        assertEq(handler.attacksChangedState(), 0, "an attack changed the registry");
    }

    /// 10. C10: the registry never holds ether, though one chair move in sixteen tries to send some.
    function invariant_10_TheRegistryHoldsNoEther() public view {
        assertEq(address(registry).balance, 0, "the registry holds ether");
    }

    /// The ghost is only worth comparing against while it is exact: every action it calls valid
    /// landed, and every action it calls invalid was refused.
    function afterInvariant() public view {
        assertEq(handler.validRefused(), 0, "the registry refused an action the model calls valid");
        assertEq(handler.invalidLanded(), 0, "the registry accepted an action the model calls invalid");
    }
}
