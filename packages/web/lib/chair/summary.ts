import { sameAccount } from "@ava/core";
import type { Hex } from "viem";
import { REGISTRY, client, getBoardAbi } from "../chain";

const isMemberAbi = [
  {
    type: "function",
    name: "isMember",
    stateMutability: "view",
    inputs: [
      { name: "boardId", type: "uint256" },
      { name: "account", type: "address" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

/** One board as the registry holds it now, and where an account stands on it. */
export interface BoardSummary {
  boardId: bigint;
  blockNumber: bigint;
  chair: Hex;
  epoch: bigint;
  memberCount: number;
  documentCount: number;
  /** "chair" when the account chairs it, "member" when it sits on it, "removed" when it was added once and is no longer on it. */
  standing: "chair" | "member" | "removed";
}

/** Reads each board's record and the account's seat at one block, so the list never mixes two moments. */
export async function summariseBoards(ids: readonly bigint[], account: Hex): Promise<BoardSummary[]> {
  if (ids.length === 0) return [];
  const blockNumber = await client.getBlockNumber();
  return Promise.all(
    ids.map(async (boardId): Promise<BoardSummary> => {
      const [board, member] = await Promise.all([
        client.readContract({ address: REGISTRY, abi: getBoardAbi, functionName: "getBoard", args: [boardId], blockNumber }),
        client.readContract({ address: REGISTRY, abi: isMemberAbi, functionName: "isMember", args: [boardId, account], blockNumber }),
      ]);
      const standing = sameAccount(board.chair, account) ? "chair" : member ? "member" : "removed";
      return { boardId, blockNumber, chair: board.chair, epoch: board.epoch, memberCount: board.memberCount, documentCount: board.documentCount, standing };
    }),
  );
}
