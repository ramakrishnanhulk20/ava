import { sameAccount } from "@ava/core";
import { parseAbiItem, type Hex } from "viem";
import { REGISTRY, client } from "../chain";
import { pause, throwIfStopped } from "../guest/time";

/** The block the BoardRegistry was deployed in, copied from packages/contracts/deployments/testnet.json. Nothing of ours is older. */
export const REGISTRY_DEPLOY_BLOCK = 10_235_963n;
const PAGE_BLOCKS = 10_000n;
const PAGES_AT_ONCE = 4;
const PAGE_TRIES = 3;
const PAGE_RETRY_MS = 1_500;
const STORAGE_PREFIX = "ava.boards.v1.";

const boardCreated = parseAbiItem("event BoardCreated(uint256 indexed boardId, address indexed chair, bytes32 boardRef, uint64 createNonce)");
const memberAdded = parseAbiItem("event MemberAdded(uint256 indexed boardId, address indexed member, uint64 epoch, uint8 mode, uint64 nonce)");

/** The boards the registry's history names an account in, and how far that history has been read. */
export interface SeenBoards {
  /** Every block up to and including this one has been read. */
  through: bigint;
  /** Boards this account created. A chair can hand a board over, so the board's own record says who chairs it now. */
  chaired: bigint[];
  /** Boards this account was ever added to. It may have been removed since; the board's own record says. */
  joined: bigint[];
}

const ascending = (ids: Iterable<bigint>): bigint[] => [...new Set(ids)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

/** The inclusive block ranges that cover `from` to `to` in pages of `size`; none when there is nothing new. */
export function pagesBetween(from: bigint, to: bigint, size: bigint): { from: bigint; to: bigint }[] {
  const pages: { from: bigint; to: bigint }[] = [];
  for (let start = from; start <= to; start += size) pages.push({ from: start, to: start + size - 1n > to ? to : start + size - 1n });
  return pages;
}

/** What was known, with a new read folded in: each board once, lowest first, and the read point never moving back. */
export function mergeBoards(known: SeenBoards | undefined, found: SeenBoards): SeenBoards {
  return {
    through: known !== undefined && known.through > found.through ? known.through : found.through,
    chaired: ascending([...(known?.chaired ?? []), ...found.chaired]),
    joined: ascending([...(known?.joined ?? []), ...found.joined]),
  };
}

export function serialiseSeen(seen: SeenBoards): string {
  return JSON.stringify({ through: seen.through.toString(), chaired: seen.chaired.map(String), joined: seen.joined.map(String) });
}

const DECIMAL = /^(0|[1-9]\d{0,30})$/;

/** The list as storage holds it, or undefined for anything that is not exactly that shape. It is public chain data and only a cache. */
export function parseSeen(raw: string | null): SeenBoards | undefined {
  if (raw === null) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const { through, chaired, joined } = parsed as Record<string, unknown>;
  const ids = (value: unknown): bigint[] | undefined => (Array.isArray(value) && value.every((v) => typeof v === "string" && DECIMAL.test(v)) ? value.map((v) => BigInt(v as string)) : undefined);
  const mine = ids(chaired);
  const theirs = ids(joined);
  if (typeof through !== "string" || !DECIMAL.test(through) || mine === undefined || theirs === undefined) return undefined;
  return { through: BigInt(through), chaired: mine, joined: theirs };
}

const storageKey = (account: Hex): string => `${STORAGE_PREFIX}${account.toLowerCase()}`;

/** What this browser remembers of an account's boards. A browser with storage off simply reads the history again. */
export function rememberedBoards(account: Hex): SeenBoards | undefined {
  try {
    return parseSeen(window.localStorage.getItem(storageKey(account)));
  } catch {
    return undefined;
  }
}

export function rememberBoards(account: Hex, seen: SeenBoards): void {
  try {
    window.localStorage.setItem(storageKey(account), serialiseSeen(seen));
  } catch {
    // Storage is only a cache here.
  }
}

async function readPage(account: Hex, page: { from: bigint; to: bigint }, signal: AbortSignal): Promise<{ chaired: bigint[]; joined: bigint[] }> {
  for (let tried = 1; ; tried++) {
    throwIfStopped(signal);
    try {
      const [created, added] = await Promise.all([
        client.getLogs({ address: REGISTRY, event: boardCreated, args: { chair: account }, fromBlock: page.from, toBlock: page.to }),
        client.getLogs({ address: REGISTRY, event: memberAdded, args: { member: account }, fromBlock: page.from, toBlock: page.to }),
      ]);
      return {
        chaired: created.filter((l) => sameAccount(l.address, REGISTRY) && l.args.boardId !== undefined).map((l) => l.args.boardId as bigint),
        joined: added.filter((l) => sameAccount(l.address, REGISTRY) && l.args.boardId !== undefined).map((l) => l.args.boardId as bigint),
      };
    } catch (error) {
      if (signal.aborted || tried >= PAGE_TRIES) throw error;
      await pause(PAGE_RETRY_MS, signal);
    }
  }
}

/**
 * Finds every board the registry's history names an account in: the boards it created and the ones
 * it was added to, read from the public EVM RPC in pages, from where the last read stopped. The
 * list comes from the chain alone; our server keeps no record of who sits on which board. A page
 * that cannot be read after three tries fails the whole read, so a list is never shown as complete
 * when part of the history is missing.
 *
 * @param known What an earlier read found, to continue from.
 * @param onPage Told after each page: how many are read, of how many.
 */
export async function findBoards(account: Hex, known: SeenBoards | undefined, signal: AbortSignal, onPage: (done: number, total: number) => void = () => undefined): Promise<SeenBoards> {
  const latest = await client.getBlockNumber();
  const from = known === undefined ? REGISTRY_DEPLOY_BLOCK : known.through + 1n;
  const pages = pagesBetween(from, latest, PAGE_BLOCKS);
  const chaired: bigint[] = [];
  const joined: bigint[] = [];
  let next = 0;
  let done = 0;
  onPage(0, pages.length);
  await Promise.all(
    Array.from({ length: Math.min(PAGES_AT_ONCE, pages.length) }, async () => {
      while (next < pages.length) {
        const page = pages[next++] as { from: bigint; to: bigint };
        const found = await readPage(account, page, signal);
        chaired.push(...found.chaired);
        joined.push(...found.joined);
        onPage(++done, pages.length);
      }
    }),
  );
  return mergeBoards(known, { through: latest, chaired, joined });
}
