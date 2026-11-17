// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {BoardRegistry} from "../../src/BoardRegistry.sol";
import {MockPqcStatus} from "../mocks/MockPqcStatus.sol";
import {PqcTestKit} from "../helpers/PqcTestKit.sol";

/// @notice Drives one BoardRegistry through random action sequences for BoardRegistryInvariant.t.sol.
/// Chair moves act as a board's chair would, with inputs drawn from the fuzzer's seeds and about one
/// in four of them deliberately wrong. Attack moves sign as someone other than the chair, replay a
/// call that landed, name another board in the signed message, or sign a nonce the board is not at.
/// Every registry call is caught here, so a refusal never ends a run.
/// @dev The ghost is this contract's own model of every board. It moves only when the model calls an
/// action valid and the registry accepted it, so a registry that accepts what the model refuses runs
/// ahead of the ghost, and the invariants see the gap. Needs MarkerVerifyMock etched first.
contract Handler is PqcTestKit {
    /// @notice One board as the model expects it.
    /// @param chair The chair.
    /// @param boardRef The board's reference.
    /// @param epoch The current epoch.
    /// @param nonce The nonce the chair's next signature covers.
    /// @param landed How many actions on the board the model accepted and the registry landed.
    /// @param members One bit per actor, by actor index.
    struct GhostBoard {
        address chair;
        bytes32 boardRef;
        uint64 epoch;
        uint64 nonce;
        uint64 landed;
        uint16 members;
    }

    // Every field any write takes, as in BoardRegistry.t.sol: `account` is the chair for CREATE, the
    // member for ADD and REMOVE and the new chair for TRANSFER; `hashA` is the envelope hash, or the
    // docRef for POST; `epoch` is epochAfter, or the document's epoch for POST.
    struct Action {
        uint8 kind;
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

    struct Landed {
        Action action;
        bytes data;
    }

    /// @notice An attack move was built from an action the model itself would refuse, so it would
    /// prove nothing. Only a bug in this handler raises it.
    error AttackBaseNotValid();
    /// @notice The handler could not seed its two starting boards.
    error SeedingFailed();

    // Copied from docs/spec/actions.md so the model never trusts the contract's own constants.
    bytes32 internal constant SPEC_TAG = 0x202301722596364529594a8773ff4f11aeb962e112437e042aa0166a90966a17;
    uint8 internal constant CREATE = 1;
    uint8 internal constant ADD = 2;
    uint8 internal constant REMOVE = 3;
    uint8 internal constant ROTATE = 4;
    uint8 internal constant POST = 5;
    uint8 internal constant TRANSFER = 6;
    uint8 internal constant SEAL_CURRENT = 0;
    uint8 internal constant ROTATE_MODE = 1;
    uint256 internal constant MAX_MEMBERS = 64;
    uint32 internal constant MAX_ENVELOPE_SIZE = 110_000;
    uint64 internal constant MAX_CIPHER_SIZE = 26_214_400;
    uint256 internal constant DEADLINE_AHEAD = 3600;

    /// @notice Actors 0 to 7 hold distinct possession-proven keys, actor 8 a key whose possession was
    /// never proven, actor 9 no key at all.
    uint256 public constant ACTOR_COUNT = 10;
    uint256 internal constant PROVEN_ACTORS = 8;
    uint256 internal constant UNPROVEN_ACTOR = 8;
    // Bounds the work of every invariant pass. Two boards exist from the start so cross-board moves
    // always have a second board.
    uint256 internal constant MAX_BOARDS = 4;
    // Signed deadlines sit 3,001 to 3,600 seconds ahead and a call moves time by at most 15 seconds,
    // so in 128 calls no landed call's deadline passes: a replay is refused for its nonce, never its age.
    uint256 internal constant MAX_TICK = 15;
    uint256 internal constant DEADLINE_SPREAD = 600;

    BoardRegistry public immutable registry;
    address[ACTOR_COUNT] internal actors;

    /// @notice How many boards the model holds.
    uint256 public ghostBoardCount;
    /// @notice The createBoard nonce the model expects for each chair.
    mapping(address chair => uint64 nonce) public ghostCreateNonce;
    mapping(uint256 boardId => GhostBoard board) internal ghostBoards;
    mapping(uint256 boardId => BoardRegistry.Document[] list) internal ghostDocuments;
    mapping(uint256 boardId => mapping(uint64 epoch => BoardRegistry.Grant[] list)) internal ghostGrants;
    mapping(uint256 boardId => mapping(bytes32 docRef => bool used)) internal ghostDocRefUsed;
    mapping(bytes32 boardRef => bool used) internal ghostBoardRefUsed;
    mapping(uint256 boardId => uint64 epoch) internal lastSeenEpoch;
    mapping(uint256 boardId => uint64[] epochs) internal epochsAtPost;
    Landed[] internal landedCalls;
    uint256 internal freshCount;

    /// @notice Chair moves the model called valid that landed.
    uint256 public validLanded;
    /// @notice Chair moves the model called invalid that were refused.
    uint256 public invalidRefused;
    /// @notice Chair moves the model called valid that the registry refused. Zero while the model is exact.
    uint256 public validRefused;
    /// @notice Chair moves the model called invalid that the registry accepted. Zero while the model is exact.
    uint256 public invalidLanded;
    /// @notice Attack moves made.
    uint256 public attacksTried;
    /// @notice Attack moves the registry accepted.
    uint256 public attacksLanded;
    /// @notice Attack moves after which anything a read can see had changed.
    uint256 public attacksChangedState;
    /// @notice Calls after which some board's epoch had moved by anything other than one step for a
    /// landed rotate, remove or rotating add on that board, and zero steps otherwise.
    uint256 public epochStepViolations;

    constructor(BoardRegistry registry_) {
        registry = registry_;
        for (uint256 i; i < ACTOR_COUNT; ++i) {
            actors[i] = makeAddr(string.concat("actor ", vm.toString(i)));
        }
        for (uint256 i; i < PROVEN_ACTORS; ++i) {
            _registerKey(actors[i], keyOf(actors[i]));
        }
        MockPqcStatus(PQC_STATUS).setKey(
            actors[UNPROVEN_ACTOR], true, PQC_ML_DSA_87, keyOf(actors[UNPROVEN_ACTOR]), false
        );
        // Both chaired by actor 0, so a signature naming one board is good on the other in every way
        // except the board id whenever their nonces meet.
        _chairMove(_createAction(actors[0], 1), 0, 0);
        _chairMove(_createAction(actors[0], 2), 0, 0);
        if (ghostBoardCount != 2) revert SeedingFailed();
    }

    // Chair moves

    /// @notice An actor creates a board. Once MAX_BOARDS exist the boardRef is always one in use.
    function create(uint256 chairSeed, uint256 inputSeed, uint256 txSeed) external {
        _tick(txSeed);
        Action memory a = _createAction(_anyone(chairSeed), inputSeed);
        if (ghostBoardCount >= MAX_BOARDS) a.boardRef = ghostBoards[_boardFrom(inputSeed)].boardRef;
        else _spoil(a, inputSeed);
        _chairMove(a, txSeed, _value(txSeed));
    }

    /// @notice The chair adds a member and seals the current epoch's key to them.
    function addSealCurrent(uint256 boardSeed, uint256 memberSeed, uint256 inputSeed, uint256 txSeed) external {
        _add(SEAL_CURRENT, boardSeed, memberSeed, inputSeed, txSeed);
    }

    /// @notice The chair adds a member and moves the board to a new epoch.
    function addRotate(uint256 boardSeed, uint256 memberSeed, uint256 inputSeed, uint256 txSeed) external {
        _add(ROTATE_MODE, boardSeed, memberSeed, inputSeed, txSeed);
    }

    /// @notice The chair removes someone: a member, the chair itself, or anyone at all.
    function remove(uint256 boardSeed, uint256 memberSeed, uint256 inputSeed, uint256 txSeed) external {
        _tick(txSeed);
        uint256 id = _boardFrom(boardSeed);
        Action memory a = _removeAction(id, _memberOrAnyone(id, memberSeed), inputSeed);
        _spoil(a, inputSeed);
        _chairMove(a, txSeed, _value(txSeed));
    }

    /// @notice The chair moves the board to a new epoch.
    function rotate(uint256 boardSeed, uint256 inputSeed, uint256 txSeed) external {
        _tick(txSeed);
        Action memory a = _rotateAction(_boardFrom(boardSeed), inputSeed);
        _spoil(a, inputSeed);
        _chairMove(a, txSeed, _value(txSeed));
    }

    /// @notice The chair posts a document.
    function post(uint256 boardSeed, uint256 inputSeed, uint256 txSeed) external {
        _tick(txSeed);
        Action memory a = _postAction(_boardFrom(boardSeed), inputSeed);
        _spoil(a, inputSeed);
        _chairMove(a, txSeed, _value(txSeed));
    }

    /// @notice The chair hands the chair to someone: a member, itself, or anyone at all.
    function transfer(uint256 boardSeed, uint256 toSeed, uint256 txSeed) external {
        _tick(txSeed);
        uint256 id = _boardFrom(boardSeed);
        _chairMove(_transferAction(id, _memberOrAnyone(id, toSeed)), txSeed, _value(txSeed));
    }

    // Attack moves. Each starts from an action the model calls valid, so the attack is the only flaw.

    /// @notice A valid action signed by anyone but the chair, with that signer's own key.
    function attackWrongSigner(uint256 boardSeed, uint256 kindSeed, uint256 signerSeed, uint256 txSeed) external {
        _tick(txSeed);
        Action memory a = _attackBase(boardSeed, kindSeed);
        address authority = _authority(a);
        uint256 pick = _bits(signerSeed, 0) % ACTOR_COUNT;
        if (actors[pick] == authority) pick = (pick + 1) % ACTOR_COUNT;
        bytes memory sig = _sign(actors[pick], a, _ghostNonce(a), _signedBoardId(a));
        _attack(a, _calldata(a, sig), txSeed);
    }

    /// @notice The exact bytes of a call that landed earlier in the run, sent again.
    function attackReplay(uint256 pickSeed, uint256 txSeed) external {
        _tick(txSeed);
        Landed memory l = landedCalls[_bits(pickSeed, 0) % landedCalls.length];
        _attack(l.action, l.data, txSeed);
    }

    /// @notice A valid action for one board, signed by its chair at its nonce, but over a message
    /// that names another board.
    function attackCrossBoard(uint256 boardSeed, uint256 otherSeed, uint256 kindSeed, uint256 txSeed) external {
        _tick(txSeed);
        uint256 target = _boardFrom(boardSeed);
        uint256 other = (target + _bits(otherSeed, 0) % (ghostBoardCount - 1)) % ghostBoardCount + 1;
        Action memory a = _validBoardAction(target, kindSeed);
        bytes memory sig = _sign(ghostBoards[target].chair, a, ghostBoards[target].nonce, other);
        _attack(a, _calldata(a, sig), txSeed);
    }

    /// @notice A valid action signed by the chair at a nonce already used, or at a future one when
    /// none has been used yet.
    function attackStaleNonce(uint256 boardSeed, uint256 kindSeed, uint256 nonceSeed, uint256 txSeed) external {
        _tick(txSeed);
        Action memory a = _attackBase(boardSeed, kindSeed);
        uint64 current = _ghostNonce(a);
        uint256 r = _bits(nonceSeed, 0);
        uint64 wrong = current > 0 && r % 4 != 0 ? uint64(r % current) : current + 1 + uint64(r % 4);
        bytes memory sig = _sign(_authority(a), a, wrong, _signedBoardId(a));
        _attack(a, _calldata(a, sig), txSeed);
    }

    // Reads for the invariant test

    /// @notice The model's view of a board.
    function ghostBoard(uint256 boardId) external view returns (GhostBoard memory) {
        return ghostBoards[boardId];
    }

    /// @notice Every document the model recorded on a board, each as it was when it landed.
    function ghostDocumentList(uint256 boardId) external view returns (BoardRegistry.Document[] memory) {
        return ghostDocuments[boardId];
    }

    /// @notice Every grant the model recorded for one epoch, each as it was when it landed.
    function ghostGrantList(uint256 boardId, uint64 epoch) external view returns (BoardRegistry.Grant[] memory) {
        return ghostGrants[boardId][epoch];
    }

    /// @notice The board's epoch on chain just before each post that landed on it, in landing order,
    /// whether or not the model called the post valid.
    function epochsWhenPosted(uint256 boardId) external view returns (uint64[] memory) {
        return epochsAtPost[boardId];
    }

    /// @notice Whether the model has `account` on the board.
    function isGhostMember(uint256 boardId, address account) external view returns (bool) {
        return _isMember(ghostBoards[boardId].members, account);
    }

    /// @notice The actor at `index`, from 0 to ACTOR_COUNT - 1.
    function actor(uint256 index) external view returns (address) {
        return actors[index];
    }

    /// @notice The stand-in ML-DSA-87 public key of `account`: 2,592 bytes, distinct per account.
    function keyOf(address account) public pure returns (bytes memory key) {
        key = new bytes(PQC_ML_DSA_87_PUBKEY_BYTES);
        bytes32 word = keccak256(abi.encode("key", account));
        assembly ("memory-safe") {
            mstore(add(key, 32), word)
        }
    }

    // The model

    function _valid(Action memory a) internal view returns (bool) {
        uint256 time = vm.getBlockTimestamp();
        if (a.deadline < time || a.deadline > time + DEADLINE_AHEAD) return false;
        if (a.kind == CREATE) {
            return _proven(a.account) && a.boardRef != bytes32(0) && !ghostBoardRefUsed[a.boardRef]
                && _envelopeOk(a);
        }
        GhostBoard storage g = ghostBoards[a.boardId];
        bool member = _isMember(g.members, a.account);
        if (a.kind == ADD) {
            if (!_proven(a.account) || member || _memberCount(g.members) >= MAX_MEMBERS || !_envelopeOk(a)) {
                return false;
            }
            if (a.mode == SEAL_CURRENT) return a.epoch == g.epoch;
            return a.mode == ROTATE_MODE && a.epoch == g.epoch + 1;
        }
        if (a.kind == REMOVE) return member && a.account != g.chair && _envelopeOk(a) && a.epoch == g.epoch + 1;
        if (a.kind == ROTATE) return _envelopeOk(a) && a.epoch == g.epoch + 1;
        if (a.kind == POST) {
            return a.hashA != bytes32(0) && a.hashB != bytes32(0) && a.cipherSize != 0
                && a.cipherSize <= MAX_CIPHER_SIZE && a.epoch == g.epoch && !ghostDocRefUsed[a.boardId][a.hashA];
        }
        return member && a.account != g.chair && _proven(a.account);
    }

    // Grants and documents take the model's epoch, not the one in the call, so a call that lands with
    // a wrong epoch shows up as a record that differs from its ghost copy.
    function _apply(Action memory a) internal {
        if (a.kind == CREATE) {
            uint256 id = ++ghostBoardCount;
            ghostBoards[id] = GhostBoard(a.account, a.boardRef, 0, 0, 0, _bit(a.account));
            ghostGrants[id][0].push(BoardRegistry.Grant(a.hashA, a.envelopeSize, ROTATE_MODE, address(0)));
            ghostBoardRefUsed[a.boardRef] = true;
            ++ghostCreateNonce[a.account];
            return;
        }
        GhostBoard storage g = ghostBoards[a.boardId];
        ++g.nonce;
        ++g.landed;
        if (a.kind == ADD) {
            g.members |= _bit(a.account);
            if (a.mode == ROTATE_MODE) ++g.epoch;
            address sealedTo = a.mode == SEAL_CURRENT ? a.account : address(0);
            ghostGrants[a.boardId][g.epoch].push(BoardRegistry.Grant(a.hashA, a.envelopeSize, a.mode, sealedTo));
        } else if (a.kind == REMOVE) {
            g.members &= ~_bit(a.account);
            ++g.epoch;
            ghostGrants[a.boardId][g.epoch].push(BoardRegistry.Grant(a.hashA, a.envelopeSize, ROTATE_MODE, address(0)));
        } else if (a.kind == ROTATE) {
            ++g.epoch;
            ghostGrants[a.boardId][g.epoch].push(BoardRegistry.Grant(a.hashA, a.envelopeSize, ROTATE_MODE, address(0)));
        } else if (a.kind == POST) {
            ghostDocuments[a.boardId].push(
                // forge-lint: disable-next-line(unsafe-typecast)
                BoardRegistry.Document(a.hashA, a.hashB, a.cipherSize, g.epoch, uint64(vm.getBlockTimestamp()))
            );
            ghostDocRefUsed[a.boardId][a.hashA] = true;
        } else {
            g.chair = a.account;
        }
    }

    function _chairMove(Action memory a, uint256 txSeed, uint256 value) internal {
        bytes memory data = _calldata(a, _sign(_authority(a), a, _ghostNonce(a), _signedBoardId(a)));
        bool valid = value == 0 && _valid(a);
        bool ok = _send(a, data, txSeed, value);
        if (ok && valid) {
            _apply(a);
            landedCalls.push(Landed(a, data));
            ++validLanded;
        } else if (ok) {
            // The ghost stays put, so the registry is now ahead of it and the invariants fail.
            ++invalidLanded;
        } else if (valid) {
            ++validRefused;
        } else {
            ++invalidRefused;
        }
        _observeEpochs(ok && _movesEpoch(a) ? a.boardId : 0);
    }

    function _attack(Action memory a, bytes memory data, uint256 txSeed) internal {
        ++attacksTried;
        bytes32 before = _registryDigest();
        bool ok = _send(a, data, txSeed, 0);
        if (ok) ++attacksLanded;
        if (_registryDigest() != before) ++attacksChangedState;
        _observeEpochs(ok && _movesEpoch(a) ? a.boardId : 0);
    }

    // Reads the board's epoch on chain just before a post, so each stored document can be checked
    // against the epoch its board really had, posts the model would refuse included.
    function _send(Action memory a, bytes memory data, uint256 txSeed, uint256 value) internal returns (bool ok) {
        uint64 epochBefore = a.kind == POST ? registry.getBoard(a.boardId).epoch : 0;
        ok = _submit(data, txSeed, value);
        if (ok && a.kind == POST) epochsAtPost[a.boardId].push(epochBefore);
    }

    // The sender is any actor, the chair included, because the sender must never matter.
    function _submit(bytes memory data, uint256 txSeed, uint256 value) internal returns (bool ok) {
        address sender = actors[_bits(txSeed, 1) % ACTOR_COUNT];
        if (value != 0) vm.deal(sender, value);
        vm.prank(sender);
        (ok,) = address(registry).call{value: value}(data);
    }

    function _observeEpochs(uint256 movedBoard) internal {
        uint256 count = registry.boardCount();
        for (uint256 id = 1; id <= count; ++id) {
            uint64 epoch = registry.getBoard(id).epoch;
            uint64 expected = lastSeenEpoch[id] + (id == movedBoard ? 1 : 0);
            if (epoch != expected) ++epochStepViolations;
            lastSeenEpoch[id] = epoch;
        }
    }

    // A rolling hash of everything a read can see: every board, member list, grant list and
    // document, and every actor's creation nonce.
    function _registryDigest() internal view returns (bytes32 h) {
        uint256 count = registry.boardCount();
        h = keccak256(abi.encode(count));
        for (uint256 id = 1; id <= count; ++id) {
            BoardRegistry.Board memory b = registry.getBoard(id);
            h = keccak256(abi.encode(h, b, registry.getMembers(id), registry.boardIdOf(b.boardRef)));
            for (uint64 e; e <= b.epoch + 1; ++e) {
                h = keccak256(abi.encode(h, registry.getGrants(id, e)));
            }
            for (uint256 d; d < b.documentCount; ++d) {
                h = keccak256(abi.encode(h, registry.getDocument(id, d)));
            }
        }
        for (uint256 i; i < ACTOR_COUNT; ++i) {
            h = keccak256(abi.encode(h, registry.createNonces(actors[i])));
        }
    }

    // Building actions

    function _add(uint8 mode, uint256 boardSeed, uint256 memberSeed, uint256 inputSeed, uint256 txSeed) internal {
        _tick(txSeed);
        uint256 id = _boardFrom(boardSeed);
        address member = _bits(memberSeed, 0) % 2 == 0 ? _newcomer(id, memberSeed) : address(0);
        if (member == address(0)) member = _anyone(memberSeed);
        Action memory a = _addAction(id, member, mode, inputSeed);
        _spoil(a, inputSeed);
        _chairMove(a, txSeed, _value(txSeed));
    }

    function _createAction(address chair, uint256 seed) internal returns (Action memory a) {
        a.kind = CREATE;
        a.account = chair;
        a.boardRef = _fresh("board ref");
        a.hashA = _fresh("envelope");
        a.envelopeSize = _envelopeSize(seed);
        a.deadline = _deadline(seed);
    }

    function _addAction(uint256 id, address member, uint8 mode, uint256 seed) internal returns (Action memory a) {
        a.kind = ADD;
        a.boardId = id;
        a.account = member;
        a.mode = mode;
        a.hashA = _fresh("envelope");
        a.envelopeSize = _envelopeSize(seed);
        a.epoch = mode == SEAL_CURRENT ? ghostBoards[id].epoch : ghostBoards[id].epoch + 1;
        a.deadline = _deadline(seed);
    }

    function _removeAction(uint256 id, address member, uint256 seed) internal returns (Action memory a) {
        a.kind = REMOVE;
        a.boardId = id;
        a.account = member;
        a.hashA = _fresh("envelope");
        a.envelopeSize = _envelopeSize(seed);
        a.epoch = ghostBoards[id].epoch + 1;
        a.deadline = _deadline(seed);
    }

    function _rotateAction(uint256 id, uint256 seed) internal returns (Action memory a) {
        a.kind = ROTATE;
        a.boardId = id;
        a.hashA = _fresh("envelope");
        a.envelopeSize = _envelopeSize(seed);
        a.epoch = ghostBoards[id].epoch + 1;
        a.deadline = _deadline(seed);
    }

    function _postAction(uint256 id, uint256 seed) internal returns (Action memory a) {
        a.kind = POST;
        a.boardId = id;
        a.hashA = _fresh("doc ref");
        a.hashB = _fresh("cipher");
        a.cipherSize = _cipherSize(seed);
        a.epoch = ghostBoards[id].epoch;
        a.deadline = _deadline(seed);
    }

    function _transferAction(uint256 id, address to) internal view returns (Action memory a) {
        a.kind = TRANSFER;
        a.boardId = id;
        a.account = to;
        a.deadline = _deadline(uint256(uint160(to)));
    }

    // One time in four, one input is wrong in a way the registry must refuse.
    function _spoil(Action memory a, uint256 seed) internal view {
        uint256 r = _bits(seed, 7);
        if (r % 4 != 0 || a.kind == TRANSFER) return;
        uint256 which = (r >> 8) % (a.kind == POST ? 7 : 5);
        uint256 extra = r >> 16;
        GhostBoard storage g = ghostBoards[a.boardId];
        if (a.kind == POST) {
            if (which == 0) a.hashA = bytes32(0);
            else if (which == 1) a.hashB = bytes32(0);
            else if (which == 2) a.cipherSize = 0;
            else if (which == 3) a.cipherSize = MAX_CIPHER_SIZE + 1 + uint64(extra % (type(uint64).max - MAX_CIPHER_SIZE));
            else if (which == 4) a.hashA = _usedDocRef(a.boardId, extra);
            else if (which == 5) a.epoch = g.epoch == 0 ? 1 : g.epoch - 1;
            else a.epoch = g.epoch + 1;
            return;
        }
        if (which == 0) a.hashA = bytes32(0);
        else if (which == 1) a.envelopeSize = 0;
        else if (which == 2) a.envelopeSize = MAX_ENVELOPE_SIZE + 1 + uint32(extra % (type(uint32).max - MAX_ENVELOPE_SIZE));
        else if (a.kind == CREATE) a.boardRef = which == 3 ? bytes32(0) : ghostBoards[_boardFrom(extra)].boardRef;
        else if (which == 3 || a.kind != ADD) a.epoch = extra % 2 == 0 ? a.epoch + 1 : _epochBelow(a.epoch);
        else a.mode = uint8(2 + extra % 254);
    }

    // One time in six a createBoard, otherwise an action on an existing board.
    function _attackBase(uint256 boardSeed, uint256 kindSeed) internal returns (Action memory a) {
        if (_bits(kindSeed, 3) % 6 != 0) return _validBoardAction(_boardFrom(boardSeed), kindSeed);
        a = _createAction(actors[_bits(boardSeed, 3) % PROVEN_ACTORS], kindSeed);
        if (!_valid(a)) revert AttackBaseNotValid();
    }

    // An action the model calls valid on `id`, of the kind the seed picks when one can be built.
    function _validBoardAction(uint256 id, uint256 seed) internal returns (Action memory a) {
        uint256 kind = _bits(seed, 4) % 5;
        address someone;
        if (kind == 0) {
            someone = _newcomer(id, seed);
            if (someone != address(0)) a = _addAction(id, someone, uint8(_bits(seed, 5) % 2), seed);
        } else if (kind == 1 || kind == 2) {
            someone = _nonChairMember(id, seed);
            if (someone != address(0)) a = kind == 1 ? _removeAction(id, someone, seed) : _transferAction(id, someone);
        } else if (kind == 3) {
            a = _postAction(id, seed);
        }
        if (a.kind == 0) a = _rotateAction(id, seed);
        if (!_valid(a)) revert AttackBaseNotValid();
    }

    function _calldata(Action memory a, bytes memory sig) internal pure returns (bytes memory) {
        if (a.kind == CREATE) {
            return abi.encodeCall(
                BoardRegistry.createBoard, (a.account, a.boardRef, a.hashA, a.envelopeSize, a.deadline, sig)
            );
        }
        if (a.kind == ADD) {
            return abi.encodeCall(
                BoardRegistry.addMember,
                (a.boardId, a.account, a.mode, a.hashA, a.envelopeSize, a.epoch, a.deadline, sig)
            );
        }
        if (a.kind == REMOVE) {
            return abi.encodeCall(
                BoardRegistry.removeMember, (a.boardId, a.account, a.hashA, a.envelopeSize, a.epoch, a.deadline, sig)
            );
        }
        if (a.kind == ROTATE) {
            return abi.encodeCall(BoardRegistry.rotateEpoch, (a.boardId, a.hashA, a.envelopeSize, a.epoch, a.deadline, sig));
        }
        if (a.kind == POST) {
            return abi.encodeCall(
                BoardRegistry.postDocument, (a.boardId, a.hashA, a.hashB, a.cipherSize, a.epoch, a.deadline, sig)
            );
        }
        return abi.encodeCall(BoardRegistry.transferChair, (a.boardId, a.account, a.deadline, sig));
    }

    // Signs the spec's message with `signer`'s own key. `boardIdInMessage` differs from the call's
    // board only in the cross-board attack.
    function _sign(address signer, Action memory a, uint64 nonce, uint256 boardIdInMessage)
        internal
        view
        returns (bytes memory)
    {
        bytes memory message = abi.encode(
            SPEC_TAG, block.chainid, address(registry), a.kind, boardIdInMessage, _paramsHash(a), nonce, a.deadline
        );
        return _markerSignature(keyOf(signer), message);
    }

    function _paramsHash(Action memory a) internal pure returns (bytes32) {
        if (a.kind == CREATE) return keccak256(abi.encode(a.account, a.boardRef, a.hashA, a.envelopeSize));
        if (a.kind == ADD) return keccak256(abi.encode(a.account, a.mode, a.hashA, a.envelopeSize, a.epoch));
        if (a.kind == REMOVE) return keccak256(abi.encode(a.account, a.hashA, a.envelopeSize, a.epoch));
        if (a.kind == ROTATE) return keccak256(abi.encode(a.hashA, a.envelopeSize, a.epoch));
        if (a.kind == POST) return keccak256(abi.encode(a.hashA, a.hashB, a.cipherSize, a.epoch));
        return keccak256(abi.encode(a.account));
    }

    // Small pieces

    function _authority(Action memory a) internal view returns (address) {
        return a.kind == CREATE ? a.account : ghostBoards[a.boardId].chair;
    }

    function _ghostNonce(Action memory a) internal view returns (uint64) {
        return a.kind == CREATE ? ghostCreateNonce[a.account] : ghostBoards[a.boardId].nonce;
    }

    function _signedBoardId(Action memory a) internal pure returns (uint256) {
        return a.kind == CREATE ? 0 : a.boardId;
    }

    function _movesEpoch(Action memory a) internal pure returns (bool) {
        return a.kind == REMOVE || a.kind == ROTATE || (a.kind == ADD && a.mode == ROTATE_MODE);
    }

    function _envelopeOk(Action memory a) internal pure returns (bool) {
        return a.hashA != bytes32(0) && a.envelopeSize != 0 && a.envelopeSize <= MAX_ENVELOPE_SIZE;
    }

    function _proven(address account) internal view returns (bool) {
        for (uint256 i; i < PROVEN_ACTORS; ++i) {
            if (actors[i] == account) return true;
        }
        return false;
    }

    function _bit(address account) internal view returns (uint16) {
        for (uint256 i; i < ACTOR_COUNT; ++i) {
            if (actors[i] == account) return uint16(1 << i);
        }
        return 0;
    }

    function _isMember(uint16 members, address account) internal view returns (bool) {
        uint16 bit = _bit(account);
        return bit != 0 && members & bit != 0;
    }

    function _memberCount(uint16 members) internal pure returns (uint256 count) {
        for (; members != 0; members &= members - 1) {
            ++count;
        }
    }

    function _boardFrom(uint256 seed) internal view returns (uint256) {
        return 1 + _bits(seed, 2) % ghostBoardCount;
    }

    // Any actor, or one time in eleven the zero address.
    function _anyone(uint256 seed) internal view returns (address) {
        uint256 i = _bits(seed, 8) % (ACTOR_COUNT + 1);
        return i == ACTOR_COUNT ? address(0) : actors[i];
    }

    // Half the time a current member, the chair included, otherwise anyone.
    function _memberOrAnyone(uint256 id, uint256 seed) internal view returns (address) {
        if (_bits(seed, 9) % 2 == 0) return _anyone(seed);
        return _pick(ghostBoards[id].members, seed);
    }

    // A proven actor who is not on the board, or address(0) when there is none.
    function _newcomer(uint256 id, uint256 seed) internal view returns (address) {
        uint16 outside = uint16((1 << PROVEN_ACTORS) - 1) & ~ghostBoards[id].members;
        return outside == 0 ? address(0) : _pick(outside, seed);
    }

    // A member other than the chair, or address(0) when there is none.
    function _nonChairMember(uint256 id, uint256 seed) internal view returns (address) {
        uint16 others = ghostBoards[id].members & ~_bit(ghostBoards[id].chair);
        return others == 0 ? address(0) : _pick(others, seed);
    }

    function _pick(uint16 mask, uint256 seed) internal view returns (address) {
        uint256 k = _bits(seed, 10) % _memberCount(mask);
        for (uint256 i; i < ACTOR_COUNT; ++i) {
            if (mask & (1 << i) == 0) continue;
            if (k == 0) return actors[i];
            --k;
        }
        return address(0);
    }

    function _usedDocRef(uint256 id, uint256 seed) internal view returns (bytes32) {
        uint256 count = ghostDocuments[id].length;
        return count == 0 ? bytes32(0) : ghostDocuments[id][seed % count].docRef;
    }

    function _epochBelow(uint64 epoch) internal pure returns (uint64) {
        return epoch == 0 ? 2 : epoch - 1;
    }

    // The edges are picked on purpose; a uniform draw from 110,000 values would almost never hit them.
    function _envelopeSize(uint256 seed) internal pure returns (uint32) {
        uint256 r = _bits(seed, 11);
        if (r % 8 == 0) return 1;
        if (r % 8 == 1) return MAX_ENVELOPE_SIZE;
        return uint32(1 + (r >> 8) % MAX_ENVELOPE_SIZE);
    }

    function _cipherSize(uint256 seed) internal pure returns (uint64) {
        uint256 r = _bits(seed, 12);
        if (r % 8 == 0) return 1;
        if (r % 8 == 1) return MAX_CIPHER_SIZE;
        return uint64(1 + (r >> 8) % MAX_CIPHER_SIZE);
    }

    function _deadline(uint256 seed) internal view returns (uint64) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(vm.getBlockTimestamp() + DEADLINE_AHEAD - _bits(seed, 13) % DEADLINE_SPREAD);
    }

    // One in sixteen chair moves carries ether, which every write must refuse.
    function _value(uint256 txSeed) internal pure returns (uint256) {
        uint256 r = _bits(txSeed, 14);
        return r % 16 == 0 ? 1 + (r >> 8) % 1 ether : 0;
    }

    function _tick(uint256 txSeed) internal {
        vm.warp(vm.getBlockTimestamp() + _bits(txSeed, 15) % (MAX_TICK + 1));
    }

    function _fresh(string memory label) internal returns (bytes32) {
        return keccak256(abi.encode(label, ++freshCount));
    }

    // The fuzzer favours small and repeated seeds, so every choice is drawn from a hash of its seed.
    function _bits(uint256 seed, uint256 salt) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(seed, salt)));
    }
}
