// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IQorePQC} from "./interfaces/IQorePQC.sol";

/// @title BoardRegistry
/// @author Ava
/// @notice Holds every Ava board: its chair, its members, its key epochs with the fingerprint of
/// every key envelope ever granted, and the fingerprint of every document posted. Every change needs
/// the chair's ML-DSA-87 signature over a message this contract builds itself, checked by QoreChain's
/// pqcVerify precompile against the key pqcKeyStatus returns for the chair. Anyone may submit a
/// signed change; the transaction sender grants nothing. No owner, no admin, no pause, no upgrade,
/// and it accepts no value. The message format is docs/spec/actions.md.
contract BoardRegistry {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice A board as getBoard returns it. Members, grants and documents are read with their own views.
    /// @param chair The account whose ML-DSA-87 key authorises every change.
    /// @param boardRef The 32 random bytes the chair picked at creation, unique in this registry. Every
    /// envelope and ciphertext is bound to the board through it, because the board id is not known
    /// when the first envelope is sealed.
    /// @param epoch The current key epoch. It starts at 0 and only goes up, by exactly one.
    /// @param nonce The nonce the chair's next signature must cover. Shared by every board action.
    /// @param memberCount How many members the board has, chair included, read from the member set.
    /// Always 1 to MAX_MEMBERS.
    /// @param documentCount How many documents have been posted. Also the next document id.
    struct Board {
        address chair;
        bytes32 boardRef;
        uint64 epoch;
        uint64 nonce;
        uint32 memberCount;
        uint32 documentCount;
    }

    // Board without memberCount: the member set is the only record of who is on a board, so the
    // count can never drift from it. Field order keeps epoch, nonce and documentCount in one slot.
    struct StoredBoard {
        address chair;
        bytes32 boardRef;
        uint64 epoch;
        uint64 nonce;
        uint32 documentCount;
    }

    /// @notice One key envelope that handed out an epoch's key.
    /// @param envelopeHash SHA-256 of the exact envelope bytes in the blob store.
    /// @param envelopeSize The envelope's length in bytes.
    /// @param mode MODE_ROTATE for an envelope sealed to every member of a new epoch, MODE_SEAL_CURRENT
    /// for the current epoch's key sealed to one member who joined mid-epoch.
    /// @param member The member a MODE_SEAL_CURRENT envelope was sealed to; address(0) for MODE_ROTATE.
    struct Grant {
        bytes32 envelopeHash;
        uint32 envelopeSize;
        uint8 mode;
        address member;
    }

    /// @notice One posted document. Its record never changes.
    /// @param docRef The 32 random bytes the chair's browser bound the document key and AAD to.
    /// @param cipherHash SHA-256 of the exact ciphertext bytes in the blob store.
    /// @param cipherSize The ciphertext's length in bytes.
    /// @param epoch The epoch whose key encrypted it, which was the board's epoch when it landed.
    /// @param postedAt The block timestamp it landed in.
    struct Document {
        bytes32 docRef;
        bytes32 cipherHash;
        uint64 cipherSize;
        uint64 epoch;
        uint64 postedAt;
    }

    /// @notice The first word of every signed message. Its first byte is 0x20, and every QoreChain
    /// reserved signing prefix starts with "q" (0x71), so no app message can be read as one of those.
    bytes32 public constant DOMAIN_TAG = keccak256("ava.board.v1");

    /// @notice Action code for createBoard.
    uint8 public constant CREATE = 1;
    /// @notice Action code for addMember.
    uint8 public constant ADD = 2;
    /// @notice Action code for removeMember.
    uint8 public constant REMOVE = 3;
    /// @notice Action code for rotateEpoch.
    uint8 public constant ROTATE = 4;
    /// @notice Action code for postDocument.
    uint8 public constant POST = 5;
    /// @notice Action code for transferChair.
    uint8 public constant TRANSFER = 6;

    /// @notice addMember mode: the current epoch's key is sealed to the new member, the epoch stays.
    uint8 public constant MODE_SEAL_CURRENT = 0;
    /// @notice addMember mode, and every epoch move: a new epoch key sealed to every member.
    uint8 public constant MODE_ROTATE = 1;

    /// @notice The most members a board can hold. Far under QoreSeal's 1,024-recipient cap, and it
    /// bounds getMembers, the grants per epoch and the largest envelope.
    uint256 public constant MAX_MEMBERS = 64;
    /// @notice The largest envelope a grant may record, in bytes. A QoreSeal envelope sealed to
    /// MAX_MEMBERS recipients is a 56-byte header plus 1,632 bytes per recipient plus a payload of
    /// at most 64 bytes: 56 + 1,632 x 64 + 64 = 104,568 bytes, rounded up to 110,000.
    uint32 public constant MAX_ENVELOPE_SIZE = 110_000;
    /// @notice The largest document ciphertext a board accepts, in bytes: 25 MiB, the product's cap.
    uint64 public constant MAX_CIPHER_SIZE = 25 * 1024 * 1024;
    /// @notice How far ahead of the current block a signed deadline may be, in seconds. One hour,
    /// so no signature outlives a testnet reset that redeploys this contract at the same address.
    uint256 public constant MAX_DEADLINE_AHEAD = 3600;

    address internal constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
    address internal constant PQC_STATUS = 0x0000000000000000000000000000000000000a02;

    uint8 private constant ML_DSA_87 = 1;
    uint256 private constant ML_DSA_87_PUBKEY_LENGTH = 2592;
    uint256 private constant ML_DSA_87_SIGNATURE_LENGTH = 4627;
    // Four ABI head words plus the length word of an empty key. The live precompile answers an
    // unregistered account with exactly this many bytes.
    uint256 private constant MIN_STATUS_RETURN_LENGTH = 160;

    /// @notice How many boards exist. Boards are numbered from 1, so this is also the newest id.
    uint256 public boardCount;

    /// @notice The nonce each chair's next createBoard signature must cover. Starts at 0 and goes up
    /// by one per board that chair creates, because a new board's id is not known when it is signed.
    mapping(address chair => uint64 nonce) public createNonces;

    mapping(uint256 boardId => StoredBoard board) private boards;
    mapping(bytes32 boardRef => uint256 boardId) private boardIdByRef;
    mapping(uint256 boardId => EnumerableSet.AddressSet set) private members;
    mapping(uint256 boardId => mapping(uint64 epoch => Grant[] list)) private grants;
    mapping(uint256 boardId => Document[] list) private documents;
    mapping(uint256 boardId => mapping(bytes32 docRef => bool used)) private usedDocRef;

    /// @notice A board was created. The chair is its first and only member, at epoch 0; no
    /// MemberAdded is emitted for the chair. An EnvelopeGranted for epoch 0 follows.
    /// @param boardId The new board's id.
    /// @param chair The chair whose key signed the creation.
    /// @param boardRef The board's random reference, unique in this registry.
    /// @param createNonce The chair's creation nonce the signature covered.
    event BoardCreated(uint256 indexed boardId, address indexed chair, bytes32 boardRef, uint64 createNonce);

    /// @notice An envelope holding an epoch's key was recorded. Grants are append-only.
    /// @param boardId The board.
    /// @param epoch The epoch whose key the envelope holds.
    /// @param envelopeHash SHA-256 of the envelope bytes.
    /// @param envelopeSize The envelope's length in bytes.
    /// @param mode MODE_ROTATE (sealed to every member) or MODE_SEAL_CURRENT (sealed to `member`).
    /// @param member The one recipient for MODE_SEAL_CURRENT; address(0) for MODE_ROTATE.
    /// @param nonce The nonce the authorising signature covered: the chair's creation nonce for a
    /// board's first grant, the board nonce for every grant after that.
    event EnvelopeGranted(
        uint256 indexed boardId,
        uint64 indexed epoch,
        bytes32 envelopeHash,
        uint32 envelopeSize,
        uint8 mode,
        address member,
        uint64 nonce
    );

    /// @notice A member joined. For MODE_ROTATE an EpochRotated follows; an EnvelopeGranted always does.
    /// @param boardId The board.
    /// @param member The new member.
    /// @param epoch The epoch the member joined at: the current one for MODE_SEAL_CURRENT, the new
    /// one for MODE_ROTATE.
    /// @param mode How the member received the key.
    /// @param nonce The board nonce the signature covered.
    event MemberAdded(uint256 indexed boardId, address indexed member, uint64 epoch, uint8 mode, uint64 nonce);

    /// @notice A member left, and the board moved to a new epoch. EpochRotated and EnvelopeGranted follow.
    /// @param boardId The board.
    /// @param member The member removed.
    /// @param newEpoch The epoch the board moved to.
    /// @param nonce The board nonce the signature covered.
    event MemberRemoved(uint256 indexed boardId, address indexed member, uint64 newEpoch, uint64 nonce);

    /// @notice The board moved to a new epoch. Emitted by every action that moves the epoch: an
    /// addMember in MODE_ROTATE, removeMember and rotateEpoch.
    /// @param boardId The board.
    /// @param newEpoch The epoch the board moved to, always the old one plus one.
    /// @param nonce The board nonce the signature covered.
    event EpochRotated(uint256 indexed boardId, uint64 indexed newEpoch, uint64 nonce);

    /// @notice A document was posted. Its record never changes.
    /// @param boardId The board.
    /// @param docId The document's id on this board, assigned in order from 0.
    /// @param docRef The document's random reference, unique on this board.
    /// @param epoch The epoch whose key encrypted it.
    /// @param cipherHash SHA-256 of the ciphertext bytes.
    /// @param cipherSize The ciphertext's length in bytes.
    /// @param nonce The board nonce the signature covered.
    event DocumentPosted(
        uint256 indexed boardId,
        uint256 indexed docId,
        bytes32 docRef,
        uint64 epoch,
        bytes32 cipherHash,
        uint64 cipherSize,
        uint64 nonce
    );

    /// @notice The chair role moved to another member. Both stay members; the epoch does not change.
    /// @param boardId The board.
    /// @param from The old chair.
    /// @param to The new chair.
    /// @param nonce The board nonce the signature covered.
    event ChairTransferred(uint256 indexed boardId, address indexed from, address indexed to, uint64 nonce);

    /// @notice No board has this id.
    error UnknownBoard(uint256 boardId);
    /// @notice The board has no document with this id.
    error UnknownDocument(uint256 boardId, uint256 docId);
    /// @notice The account has no post-quantum key on file.
    error NoPqcKey(address account);
    /// @notice The account's key is not ML-DSA-87.
    error WrongAlgorithm(address account, uint8 algorithmId);
    /// @notice The account's key was registered without a proof of possession.
    error PossessionNotProven(address account);
    /// @notice The account's registered key is not 2,592 bytes.
    error BadKeyLength(address account, uint256 length);
    /// @notice A precompile reverted, or answered with empty, short or malformed data.
    error PrecompileUnavailable(address precompile);
    /// @notice The signature is not 4,627 bytes, or does not verify under `signer`'s key for the
    /// message this contract builds. A replayed signature fails here, because the nonce has moved.
    error BadSignature(address signer);
    /// @notice The signed deadline is before the current block's timestamp.
    error DeadlineExpired(uint64 deadline, uint256 timestamp);
    /// @notice The signed deadline is more than MAX_DEADLINE_AHEAD after the current block's timestamp.
    error DeadlineTooFar(uint64 deadline, uint256 latestAllowed);
    /// @notice The epoch named in the call is not the one this action requires.
    error WrongEpoch(uint64 expected, uint64 given);
    /// @notice The addMember mode is neither MODE_SEAL_CURRENT nor MODE_ROTATE.
    error BadMode(uint8 mode);
    /// @notice The account is already a member of the board.
    error AlreadyMember(uint256 boardId, address account);
    /// @notice The account is not a member of the board.
    error NotMember(uint256 boardId, address account);
    /// @notice The chair cannot be removed. Transfer the chair role first.
    error ChairCannotLeave(uint256 boardId, address chair);
    /// @notice The board already holds MAX_MEMBERS members.
    error BoardFull(uint256 boardId, uint256 maxMembers);
    /// @notice An address argument is address(0).
    error ZeroAddress();
    /// @notice A hash or docRef argument is zero.
    error ZeroHash();
    /// @notice The envelope size is 0 or above MAX_ENVELOPE_SIZE.
    error BadEnvelopeSize(uint32 size);
    /// @notice The ciphertext size is 0 or above MAX_CIPHER_SIZE.
    error BadCipherSize(uint64 size);
    /// @notice The docRef was already used on this board.
    error DocRefUsed(uint256 boardId, bytes32 docRef);
    /// @notice The boardRef was already used by a board in this registry.
    error BoardRefUsed(bytes32 boardRef);
    /// @notice The new chair is already the chair.
    error SameChair(uint256 boardId, address chair);

    /// @notice Creates a board with `chair` as its only member at epoch 0, and records the envelope
    /// that seals epoch 0's key to the chair. Anyone may submit; the chair's signature is the authority.
    /// @dev Signed message: action CREATE, boardId 0, paramsCreate(chair, boardRef, envelopeHash,
    /// envelopeSize), nonce createNonces[chair]. Reverts ZeroAddress for a zero chair; ZeroHash for a
    /// zero boardRef or envelope hash; BoardRefUsed if any board already has this boardRef;
    /// BadEnvelopeSize for a size of 0 or above MAX_ENVELOPE_SIZE; DeadlineExpired or
    /// DeadlineTooFar outside [block.timestamp, block.timestamp + MAX_DEADLINE_AHEAD]; NoPqcKey,
    /// WrongAlgorithm, PossessionNotProven or BadKeyLength unless the chair holds a possession-proven
    /// 2,592-byte ML-DSA-87 key; BadSignature for a signature that is not 4,627 bytes or does not
    /// verify; PrecompileUnavailable if either precompile reverts or answers with empty or short data.
    /// Emits BoardCreated, then EnvelopeGranted (epoch 0, MODE_ROTATE, member 0). Moves
    /// createNonces[chair] up by one.
    /// @param chair The board's chair and first member, and the account whose key must have signed.
    /// @param boardRef 32 random bytes the chair picked, unique in this registry.
    /// @param envelopeHash SHA-256 of the epoch 0 envelope bytes.
    /// @param envelopeSize The epoch 0 envelope's length in bytes.
    /// @param deadline Unix seconds after which the signature is refused.
    /// @param signature The chair's 4,627-byte ML-DSA-87 signature over the message.
    /// @return boardId The new board's id, which is the new boardCount.
    function createBoard(
        address chair,
        bytes32 boardRef,
        bytes32 envelopeHash,
        uint32 envelopeSize,
        uint64 deadline,
        bytes calldata signature
    ) external returns (uint256 boardId) {
        if (chair == address(0)) revert ZeroAddress();
        if (boardRef == bytes32(0)) revert ZeroHash();
        if (boardIdByRef[boardRef] != 0) revert BoardRefUsed(boardRef);
        _checkEnvelope(envelopeHash, envelopeSize);
        bytes32 paramsHash = paramsCreate(chair, boardRef, envelopeHash, envelopeSize);
        uint64 nonce = createNonces[chair];
        _authorise(chair, CREATE, 0, paramsHash, nonce, deadline, signature);

        createNonces[chair] = nonce + 1;
        boardId = ++boardCount;
        boardIdByRef[boardRef] = boardId;
        StoredBoard storage board = boards[boardId];
        board.chair = chair;
        board.boardRef = boardRef;
        _addMember(boardId, chair);
        grants[boardId][0].push(Grant(envelopeHash, envelopeSize, MODE_ROTATE, address(0)));

        emit BoardCreated(boardId, chair, boardRef, nonce);
        emit EnvelopeGranted(boardId, 0, envelopeHash, envelopeSize, MODE_ROTATE, address(0), nonce);
    }

    /// @notice Adds a member who holds a possession-proven ML-DSA-87 key. In MODE_SEAL_CURRENT the
    /// current epoch's key is sealed to the new member and the epoch stays; in MODE_ROTATE the board
    /// moves to a new epoch whose key is sealed to every member, the new one included.
    /// @dev Signed message: action ADD, paramsAdd(member, mode, envelopeHash, envelopeSize,
    /// epochAfter), the board nonce. Reverts UnknownBoard; ZeroAddress for a zero member;
    /// AlreadyMember; BoardFull at MAX_MEMBERS; ZeroHash; BadEnvelopeSize; WrongEpoch unless
    /// epochAfter is the current epoch (MODE_SEAL_CURRENT) or the current epoch plus one (MODE_ROTATE);
    /// BadMode for any other mode; NoPqcKey, WrongAlgorithm, PossessionNotProven or BadKeyLength for
    /// the member's key, then for the chair's; DeadlineExpired, DeadlineTooFar, BadSignature and
    /// PrecompileUnavailable as for createBoard. Emits MemberAdded, then EpochRotated (MODE_ROTATE
    /// only), then EnvelopeGranted (member set for MODE_SEAL_CURRENT, address(0) for MODE_ROTATE).
    /// Appends the grant to epochAfter's list and never replaces one. Moves the board nonce up by one.
    /// @param boardId The board.
    /// @param member The account to add.
    /// @param mode MODE_SEAL_CURRENT or MODE_ROTATE.
    /// @param envelopeHash SHA-256 of the envelope bytes.
    /// @param envelopeSize The envelope's length in bytes.
    /// @param epochAfter The board's epoch once this lands.
    /// @param deadline Unix seconds after which the signature is refused.
    /// @param signature The chair's 4,627-byte ML-DSA-87 signature over the message.
    function addMember(
        uint256 boardId,
        address member,
        uint8 mode,
        bytes32 envelopeHash,
        uint32 envelopeSize,
        uint64 epochAfter,
        uint64 deadline,
        bytes calldata signature
    ) external {
        StoredBoard storage board = _board(boardId);
        if (member == address(0)) revert ZeroAddress();
        if (members[boardId].contains(member)) revert AlreadyMember(boardId, member);
        if (members[boardId].length() >= MAX_MEMBERS) revert BoardFull(boardId, MAX_MEMBERS);
        _checkEnvelope(envelopeHash, envelopeSize);
        if (mode == MODE_SEAL_CURRENT) {
            if (epochAfter != board.epoch) revert WrongEpoch(board.epoch, epochAfter);
        } else if (mode == MODE_ROTATE) {
            _checkNextEpoch(board, epochAfter);
        } else {
            revert BadMode(mode);
        }
        _provenKey(member);
        bytes32 paramsHash = paramsAdd(member, mode, envelopeHash, envelopeSize, epochAfter);
        uint64 nonce = board.nonce;
        _authorise(board.chair, ADD, boardId, paramsHash, nonce, deadline, signature);

        board.nonce = nonce + 1;
        board.epoch = epochAfter;
        _addMember(boardId, member);
        address sealedTo = mode == MODE_SEAL_CURRENT ? member : address(0);
        grants[boardId][epochAfter].push(Grant(envelopeHash, envelopeSize, mode, sealedTo));

        emit MemberAdded(boardId, member, epochAfter, mode, nonce);
        if (mode == MODE_ROTATE) emit EpochRotated(boardId, epochAfter, nonce);
        emit EnvelopeGranted(boardId, epochAfter, envelopeHash, envelopeSize, mode, sealedTo, nonce);
    }

    /// @notice Removes a member and moves the board to a new epoch whose key is sealed to the members
    /// who remain, so documents posted from now on are closed to the removed member.
    /// @dev Signed message: action REMOVE, paramsRemove(member, envelopeHash, envelopeSize,
    /// epochAfter), the board nonce. Reverts UnknownBoard; ZeroAddress; ChairCannotLeave for the
    /// chair; NotMember; ZeroHash; BadEnvelopeSize; WrongEpoch unless epochAfter is the current epoch
    /// plus one; then the chair's key and signature checks as for createBoard. Emits MemberRemoved,
    /// EpochRotated, then EnvelopeGranted (MODE_ROTATE, member 0). Moves the board nonce up by one.
    /// @param boardId The board.
    /// @param member The member to remove.
    /// @param envelopeHash SHA-256 of the new epoch's envelope bytes.
    /// @param envelopeSize The new epoch's envelope length in bytes.
    /// @param epochAfter The board's epoch once this lands: the current epoch plus one.
    /// @param deadline Unix seconds after which the signature is refused.
    /// @param signature The chair's 4,627-byte ML-DSA-87 signature over the message.
    function removeMember(
        uint256 boardId,
        address member,
        bytes32 envelopeHash,
        uint32 envelopeSize,
        uint64 epochAfter,
        uint64 deadline,
        bytes calldata signature
    ) external {
        StoredBoard storage board = _board(boardId);
        if (member == address(0)) revert ZeroAddress();
        if (member == board.chair) revert ChairCannotLeave(boardId, member);
        if (!members[boardId].contains(member)) revert NotMember(boardId, member);
        _checkEnvelope(envelopeHash, envelopeSize);
        _checkNextEpoch(board, epochAfter);
        bytes32 paramsHash = paramsRemove(member, envelopeHash, envelopeSize, epochAfter);
        uint64 nonce = board.nonce;
        _authorise(board.chair, REMOVE, boardId, paramsHash, nonce, deadline, signature);

        board.nonce = nonce + 1;
        board.epoch = epochAfter;
        _removeMember(boardId, member);
        grants[boardId][epochAfter].push(Grant(envelopeHash, envelopeSize, MODE_ROTATE, address(0)));

        emit MemberRemoved(boardId, member, epochAfter, nonce);
        emit EpochRotated(boardId, epochAfter, nonce);
        emit EnvelopeGranted(boardId, epochAfter, envelopeHash, envelopeSize, MODE_ROTATE, address(0), nonce);
    }

    /// @notice Moves the board to a new epoch with a fresh key sealed to every current member.
    /// @dev Signed message: action ROTATE, paramsRotate(envelopeHash, envelopeSize, epochAfter), the
    /// board nonce. Reverts UnknownBoard; ZeroHash; BadEnvelopeSize; WrongEpoch unless epochAfter is
    /// the current epoch plus one; then the chair's key and signature checks as for createBoard.
    /// Emits EpochRotated, then EnvelopeGranted (MODE_ROTATE, member 0). Moves the board nonce up by one.
    /// @param boardId The board.
    /// @param envelopeHash SHA-256 of the new epoch's envelope bytes.
    /// @param envelopeSize The new epoch's envelope length in bytes.
    /// @param epochAfter The board's epoch once this lands: the current epoch plus one.
    /// @param deadline Unix seconds after which the signature is refused.
    /// @param signature The chair's 4,627-byte ML-DSA-87 signature over the message.
    function rotateEpoch(
        uint256 boardId,
        bytes32 envelopeHash,
        uint32 envelopeSize,
        uint64 epochAfter,
        uint64 deadline,
        bytes calldata signature
    ) external {
        StoredBoard storage board = _board(boardId);
        _checkEnvelope(envelopeHash, envelopeSize);
        _checkNextEpoch(board, epochAfter);
        bytes32 paramsHash = paramsRotate(envelopeHash, envelopeSize, epochAfter);
        uint64 nonce = board.nonce;
        _authorise(board.chair, ROTATE, boardId, paramsHash, nonce, deadline, signature);

        board.nonce = nonce + 1;
        board.epoch = epochAfter;
        grants[boardId][epochAfter].push(Grant(envelopeHash, envelopeSize, MODE_ROTATE, address(0)));

        emit EpochRotated(boardId, epochAfter, nonce);
        emit EnvelopeGranted(boardId, epochAfter, envelopeHash, envelopeSize, MODE_ROTATE, address(0), nonce);
    }

    /// @notice Records a document's ciphertext fingerprint under the board's current epoch.
    /// @dev Signed message: action POST, paramsPost(docRef, cipherHash, cipherSize, epoch), the board
    /// nonce. Reverts UnknownBoard; ZeroHash for a zero docRef or cipherHash; BadCipherSize for a size
    /// of 0 or above MAX_CIPHER_SIZE; WrongEpoch unless `epoch` is the board's epoch when this lands,
    /// so a document signed before a removal can never land under the old key after it; DocRefUsed
    /// if the docRef was used on this board; then the chair's key and signature checks as for
    /// createBoard. Emits DocumentPosted. Moves the board nonce up by one.
    /// @param boardId The board.
    /// @param docRef The 32 random bytes the document key and AAD are bound to.
    /// @param cipherHash SHA-256 of the ciphertext bytes.
    /// @param cipherSize The ciphertext's length in bytes.
    /// @param epoch The epoch whose key encrypted the document.
    /// @param deadline Unix seconds after which the signature is refused.
    /// @param signature The chair's 4,627-byte ML-DSA-87 signature over the message.
    /// @return docId The document's id: the board's documentCount before this post.
    function postDocument(
        uint256 boardId,
        bytes32 docRef,
        bytes32 cipherHash,
        uint64 cipherSize,
        uint64 epoch,
        uint64 deadline,
        bytes calldata signature
    ) external returns (uint256 docId) {
        StoredBoard storage board = _board(boardId);
        if (docRef == bytes32(0) || cipherHash == bytes32(0)) revert ZeroHash();
        if (cipherSize == 0 || cipherSize > MAX_CIPHER_SIZE) revert BadCipherSize(cipherSize);
        if (epoch != board.epoch) revert WrongEpoch(board.epoch, epoch);
        if (usedDocRef[boardId][docRef]) revert DocRefUsed(boardId, docRef);
        bytes32 paramsHash = paramsPost(docRef, cipherHash, cipherSize, epoch);
        uint64 nonce = board.nonce;
        _authorise(board.chair, POST, boardId, paramsHash, nonce, deadline, signature);

        board.nonce = nonce + 1;
        uint32 count = board.documentCount;
        board.documentCount = count + 1;
        docId = count;
        usedDocRef[boardId][docRef] = true;
        // Casting to uint64 is safe because seconds since 1970 fit in 64 bits for billions of years.
        // forge-lint: disable-next-line(unsafe-typecast)
        documents[boardId].push(Document(docRef, cipherHash, cipherSize, epoch, uint64(block.timestamp)));

        emit DocumentPosted(boardId, docId, docRef, epoch, cipherHash, cipherSize, nonce);
    }

    /// @notice Hands the chair role to another member whose key is possession-proven now. The old
    /// chair stays a member, and the new chair can then remove it.
    /// @dev Signed message: action TRANSFER, paramsTransfer(newChair), the board nonce, signed by the
    /// current chair. Reverts UnknownBoard; ZeroAddress; SameChair; NotMember unless newChair is a
    /// member; NoPqcKey, WrongAlgorithm, PossessionNotProven or BadKeyLength for newChair's key, then
    /// for the chair's; DeadlineExpired, DeadlineTooFar, BadSignature and PrecompileUnavailable as for
    /// createBoard. Emits ChairTransferred. Moves the board nonce up by one; the epoch does not change.
    /// @param boardId The board.
    /// @param newChair The member who becomes chair.
    /// @param deadline Unix seconds after which the signature is refused.
    /// @param signature The current chair's 4,627-byte ML-DSA-87 signature over the message.
    function transferChair(uint256 boardId, address newChair, uint64 deadline, bytes calldata signature) external {
        StoredBoard storage board = _board(boardId);
        if (newChair == address(0)) revert ZeroAddress();
        address chair = board.chair;
        if (newChair == chair) revert SameChair(boardId, chair);
        if (!members[boardId].contains(newChair)) revert NotMember(boardId, newChair);
        _provenKey(newChair);
        bytes32 paramsHash = paramsTransfer(newChair);
        uint64 nonce = board.nonce;
        _authorise(chair, TRANSFER, boardId, paramsHash, nonce, deadline, signature);

        board.nonce = nonce + 1;
        board.chair = newChair;

        emit ChairTransferred(boardId, chair, newChair, nonce);
    }

    /// @notice The exact 256 bytes a chair signs for an action: abi.encode(DOMAIN_TAG, block.chainid,
    /// this contract, action, boardId, paramsHash, nonce, deadline), per docs/spec/actions.md.
    /// @dev Builds bytes for any inputs and checks none of them; the writes check everything.
    /// @param action The action code, CREATE to TRANSFER.
    /// @param boardId The board id, or 0 for CREATE.
    /// @param paramsHash The hash from the matching params function.
    /// @param nonce createNonces[chair] for CREATE, the board's nonce for every other action.
    /// @param deadline Unix seconds after which the signature is refused.
    /// @return The message to sign with pure ML-DSA-87, empty context, no prehash.
    function actionMessage(uint8 action, uint256 boardId, bytes32 paramsHash, uint64 nonce, uint64 deadline)
        external
        view
        returns (bytes memory)
    {
        return _message(action, boardId, paramsHash, nonce, deadline);
    }

    /// @notice The paramsHash for createBoard:
    /// keccak256(abi.encode(chair, boardRef, envelopeHash, envelopeSize)).
    /// @param chair The board's chair.
    /// @param boardRef The board's random reference.
    /// @param envelopeHash SHA-256 of the epoch 0 envelope bytes.
    /// @param envelopeSize The envelope's length in bytes.
    /// @return The paramsHash.
    function paramsCreate(address chair, bytes32 boardRef, bytes32 envelopeHash, uint32 envelopeSize)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(chair, boardRef, envelopeHash, envelopeSize));
    }

    /// @notice The paramsHash for addMember:
    /// keccak256(abi.encode(member, mode, envelopeHash, envelopeSize, epochAfter)).
    /// @param member The account to add.
    /// @param mode MODE_SEAL_CURRENT or MODE_ROTATE.
    /// @param envelopeHash SHA-256 of the envelope bytes.
    /// @param envelopeSize The envelope's length in bytes.
    /// @param epochAfter The board's epoch once the add lands.
    /// @return The paramsHash.
    function paramsAdd(address member, uint8 mode, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(member, mode, envelopeHash, envelopeSize, epochAfter));
    }

    /// @notice The paramsHash for removeMember:
    /// keccak256(abi.encode(member, envelopeHash, envelopeSize, epochAfter)).
    /// @param member The member to remove.
    /// @param envelopeHash SHA-256 of the new epoch's envelope bytes.
    /// @param envelopeSize The envelope's length in bytes.
    /// @param epochAfter The board's epoch once the removal lands.
    /// @return The paramsHash.
    function paramsRemove(address member, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(member, envelopeHash, envelopeSize, epochAfter));
    }

    /// @notice The paramsHash for rotateEpoch: keccak256(abi.encode(envelopeHash, envelopeSize, epochAfter)).
    /// @param envelopeHash SHA-256 of the new epoch's envelope bytes.
    /// @param envelopeSize The envelope's length in bytes.
    /// @param epochAfter The board's epoch once the rotation lands.
    /// @return The paramsHash.
    function paramsRotate(bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter) public pure returns (bytes32) {
        return keccak256(abi.encode(envelopeHash, envelopeSize, epochAfter));
    }

    /// @notice The paramsHash for postDocument: keccak256(abi.encode(docRef, cipherHash, cipherSize, epoch)).
    /// @param docRef The document's random reference.
    /// @param cipherHash SHA-256 of the ciphertext bytes.
    /// @param cipherSize The ciphertext's length in bytes.
    /// @param epoch The epoch whose key encrypted the document.
    /// @return The paramsHash.
    function paramsPost(bytes32 docRef, bytes32 cipherHash, uint64 cipherSize, uint64 epoch)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(docRef, cipherHash, cipherSize, epoch));
    }

    /// @notice The paramsHash for transferChair: keccak256(abi.encode(newChair)).
    /// @param newChair The member who becomes chair.
    /// @return The paramsHash.
    function paramsTransfer(address newChair) public pure returns (bytes32) {
        return keccak256(abi.encode(newChair));
    }

    /// @notice Whether `boardId` is a board this registry made. Any other id, and any board in any
    /// other contract, is unknown.
    /// @param boardId The id to check.
    /// @return True for 1 to boardCount.
    function exists(uint256 boardId) public view returns (bool) {
        return boardId != 0 && boardId <= boardCount;
    }

    /// @notice The board that holds `boardRef`, so a client can find a board from the reference its
    /// ciphertexts are bound to.
    /// @param boardRef The reference to look up.
    /// @return The board id, or 0 when no board in this registry uses that reference.
    function boardIdOf(bytes32 boardRef) external view returns (uint256) {
        return boardIdByRef[boardRef];
    }

    /// @notice Reads a board's chair, boardRef, epoch, nonce, member count and document count.
    /// @dev Reverts UnknownBoard for an id this registry did not make.
    /// @param boardId The board.
    /// @return The board.
    function getBoard(uint256 boardId) external view returns (Board memory) {
        StoredBoard storage board = _board(boardId);
        // The set never holds more than MAX_MEMBERS (64), so the count fits in 32 bits.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint32 memberCount = uint32(members[boardId].length());
        return Board(board.chair, board.boardRef, board.epoch, board.nonce, memberCount, board.documentCount);
    }

    /// @notice Whether `account` is a member of the board. False for unknown boards and address(0).
    /// @param boardId The board.
    /// @param account The account to check.
    /// @return True only for a current member.
    function isMember(uint256 boardId, address account) external view returns (bool) {
        return members[boardId].contains(account);
    }

    /// @notice Lists a board's current members, chair included. Order is not meaningful: a removal
    /// moves the last member into the leaving member's place.
    /// @dev Never more than MAX_MEMBERS entries. Reverts UnknownBoard for an id this registry did not make.
    /// @param boardId The board.
    /// @return The members.
    function getMembers(uint256 boardId) external view returns (address[] memory) {
        _requireBoard(boardId);
        return members[boardId].values();
    }

    /// @notice Lists every envelope ever granted for one epoch, in the order they landed. The first is
    /// the MODE_ROTATE envelope that opened the epoch; any after it are MODE_SEAL_CURRENT envelopes
    /// for members who joined during it.
    /// @dev At most MAX_MEMBERS entries: after the first, each one adds a member, and only a removal
    /// frees a place, which moves the board to a new epoch. Empty for an epoch the board has not
    /// reached. Reverts UnknownBoard for an id this registry did not make.
    /// @param boardId The board.
    /// @param epoch The epoch.
    /// @return The grants.
    function getGrants(uint256 boardId, uint64 epoch) external view returns (Grant[] memory) {
        _requireBoard(boardId);
        return grants[boardId][epoch];
    }

    /// @notice Reads one posted document.
    /// @dev Reverts UnknownBoard for an id this registry did not make, and UnknownDocument when docId
    /// is not below the board's documentCount.
    /// @param boardId The board.
    /// @param docId The document id, from 0 to documentCount - 1.
    /// @return The document.
    function getDocument(uint256 boardId, uint256 docId) external view returns (Document memory) {
        _requireBoard(boardId);
        Document[] storage list = documents[boardId];
        if (docId >= list.length) revert UnknownDocument(boardId, docId);
        return list[docId];
    }

    function _message(uint8 action, uint256 boardId, bytes32 paramsHash, uint64 nonce, uint64 deadline)
        private
        view
        returns (bytes memory)
    {
        return abi.encode(DOMAIN_TAG, block.chainid, address(this), action, boardId, paramsHash, nonce, deadline);
    }

    // Low-level calls on purpose: an inactive precompile answers a call with success and empty
    // data, which a high-level call would not let us tell apart from a real answer.
    function _provenKey(address account) private view returns (bytes memory pubkey) {
        (bool ok, bytes memory ret) = PQC_STATUS.staticcall(abi.encodeCall(IQorePQC.pqcKeyStatus, (account)));
        if (!ok || ret.length < MIN_STATUS_RETURN_LENGTH) revert PrecompileUnavailable(PQC_STATUS);

        bool registered;
        uint8 algorithmId;
        bool possessionProven;
        (registered, algorithmId, pubkey, possessionProven) = abi.decode(ret, (bool, uint8, bytes, bool));

        if (!registered) revert NoPqcKey(account);
        if (algorithmId != ML_DSA_87) revert WrongAlgorithm(account, algorithmId);
        if (!possessionProven) revert PossessionNotProven(account);
        if (pubkey.length != ML_DSA_87_PUBKEY_LENGTH) revert BadKeyLength(account, pubkey.length);
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

    // The one gate every write passes. Replay protection lives in the nonce inside the message,
    // never in the signature bytes, because ML-DSA can produce many valid signatures for one message.
    function _authorise(
        address signer,
        uint8 action,
        uint256 boardId,
        bytes32 paramsHash,
        uint64 nonce,
        uint64 deadline,
        bytes calldata signature
    ) private view {
        _checkDeadline(deadline);
        bytes memory pubkey = _provenKey(signer);
        if (signature.length != ML_DSA_87_SIGNATURE_LENGTH) revert BadSignature(signer);
        if (!_verify(pubkey, signature, _message(action, boardId, paramsHash, nonce, deadline))) {
            revert BadSignature(signer);
        }
    }

    // Validators can nudge block.timestamp by seconds; against a one-hour window that does not matter.
    function _checkDeadline(uint64 deadline) private view {
        // forge-lint: disable-next-line(block-timestamp)
        if (deadline < block.timestamp) revert DeadlineExpired(deadline, block.timestamp);
        uint256 latestAllowed = block.timestamp + MAX_DEADLINE_AHEAD;
        // forge-lint: disable-next-line(block-timestamp)
        if (deadline > latestAllowed) revert DeadlineTooFar(deadline, latestAllowed);
    }

    // The callers check membership first so their errors come in a fixed order. The set's own answer
    // is checked as well, so a duplicate add or a missing removal can never pass silently.
    function _addMember(uint256 boardId, address account) private {
        if (!members[boardId].add(account)) revert AlreadyMember(boardId, account);
    }

    // EnumerableSet removes by swap-and-pop: the last member takes the leaving member's place.
    function _removeMember(uint256 boardId, address account) private {
        if (!members[boardId].remove(account)) revert NotMember(boardId, account);
    }

    function _board(uint256 boardId) private view returns (StoredBoard storage) {
        _requireBoard(boardId);
        return boards[boardId];
    }

    function _requireBoard(uint256 boardId) private view {
        if (!exists(boardId)) revert UnknownBoard(boardId);
    }

    function _checkEnvelope(bytes32 envelopeHash, uint32 envelopeSize) private pure {
        if (envelopeHash == bytes32(0)) revert ZeroHash();
        if (envelopeSize == 0 || envelopeSize > MAX_ENVELOPE_SIZE) revert BadEnvelopeSize(envelopeSize);
    }

    // Every epoch move is exactly one step and is named in the signed message, so a stale signature
    // can never skip or repeat an epoch.
    function _checkNextEpoch(StoredBoard storage board, uint64 epochAfter) private view {
        uint64 next = board.epoch + 1;
        if (epochAfter != next) revert WrongEpoch(next, epochAfter);
    }
}
