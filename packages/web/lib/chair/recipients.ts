import { sameAccount, type KemRecipient } from "@ava/core";
import type { Hex } from "viem";

/**
 * Who a new epoch's key is sealed to (threat model C15, C17): every member of the board as read at
 * one block, less the one being removed, plus the one being added, each exactly once. A member
 * whose key was not read stops the rotation; the list is never quietly made shorter, because that
 * would lock a director out without a removal anyone signed.
 *
 * @param members The board's members at the block the action is built from.
 * @param keys What fetchKemKey answered for those members; extra entries are ignored.
 * @throws Error when a member has no key in `keys`, the board read lists an account twice, the one
 *   to remove is not a member, or the one to add already is.
 */
export function rotationRecipients(members: readonly Hex[], keys: readonly KemRecipient[], change: { remove?: Hex; add?: KemRecipient }): KemRecipient[] {
  const { remove, add } = change;
  if (members.some((m, i) => members.findIndex((n) => sameAccount(m, n)) !== i)) throw new Error("The board read lists one account twice.");
  if (remove !== undefined && !members.some((m) => sameAccount(m, remove))) throw new Error(`${remove} is not a member of this board.`);
  if (add !== undefined && members.some((m) => sameAccount(m, add.address))) throw new Error(`${add.address} is already a member of this board.`);
  const out: KemRecipient[] = [];
  for (const member of members) {
    if (remove !== undefined && sameAccount(member, remove)) continue;
    const found = keys.find((k) => sameAccount(k.address, member));
    if (found === undefined) throw new Error(`No ML-KEM key was read for the member ${member}, so the new key cannot be sealed to the whole board.`);
    out.push(found);
  }
  if (add !== undefined) out.push(add);
  return out;
}
