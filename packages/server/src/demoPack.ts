/**
 * The demo pack's plain text: the exact bytes, encoded as UTF-8, that ensureCurrentPack encrypts
 * for every epoch (threat model C33). A string in the code rather than a file read at run time, so
 * the app's server bundle and its deploy's file tracing can never leave it out.
 */
export const DEMO_PACK_TEXT = `Ava demo board: board pack

A memo from the chair to every member of the demo board.

Agenda
1. Approve the quarter's plan.
2. Review the move to post-quantum keys.
3. Any other business.

The plan for the quarter keeps the three goals the board agreed last time. We bring the member app to the first ten companies on the waiting list, we cut the time it takes a new director to join a board from a day to a few minutes, and we hold running costs where they are today. The chair asks the board to approve the plan as written. A director who wants a change should raise it under item three, so the plan itself is voted on once and the minutes stay short.

On keys, every member of this board now signs with ML-DSA-87 and receives board papers sealed with ML-KEM-1024, the post-quantum standards NIST published in 2024. A recording of today's traffic cannot be opened later by a quantum computer, which is the risk that made us move first. Each time a member leaves, the board moves to a new key, so a former member cannot read anything posted after they left. The chair proposes that the board keeps this rule for every pack it shares, and that no board paper goes out by email again.

No real company, figures or people appear in this memo.

This pack is demo content, sealed to everyone on the board at the epoch it was posted.
`;
