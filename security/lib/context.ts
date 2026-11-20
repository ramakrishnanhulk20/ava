import { Mode, deadlineFrom, newBoardRef, newEpochKey, paramsAdd, paramsCreate } from "@ava/core";
import { bytesToHex, type Hex, type PublicClient } from "viem";
import type { SetupName } from "./attack.ts";
import type { Challenge } from "./demo.ts";
import { WalletLane, balanceOf, evmClient, registryEvents } from "./chain.ts";
import { SourceIps } from "./dev.ts";
import type { SuiteEnv } from "./env.ts";
import { ROLES, personAt, type Person, type Role } from "./identities.ts";
import { People } from "./people.ts";
import { Action, DEADLINE_SECONDS, LocalBlobs, boardAt, calldata, createNonceOf, sealTo, sign, type EpochKey } from "./registry.ts";

/** The wallet never goes below this, so it can always close its window at the end. */
export const WALLET_FLOOR_UQOR = 300_000n;

export interface AddArgs {
  boardId: bigint;
  member: Hex;
  mode: number;
  envelopeHash: Hex;
  envelopeSize: number;
  epochAfter: bigint;
  deadline: bigint;
  signature: Hex;
}

/** Boards A and B, made fresh each run with the wallet as chair. B stays at epoch 0 and nonce 0 for the cross-board replay. */
export interface TestBoards {
  a: bigint;
  b: bigint;
  aCreateHash: Hex;
  /** Dana's landed MODE_ROTATE addMember on A, signed at A's nonce 0, epoch 0 to 1. */
  addDana: { hash: Hex; args: AddArgs };
  /** Every epoch key this run made, by `${boardId}:${epoch}`. */
  keys: Map<string, EpochKey>;
}

/** What one attack hands a later one. */
export interface SuiteState {
  boards?: TestBoards;
  /** C5's landed removal of Eli, replayed by C2-replay. */
  removal?: { hash: Hex };
  /** The relayer as the chain shows it in the C24 transaction. */
  relayer?: { qor1: string; evm: Hex };
  /** The real envelope C28's control uploaded, read back by C29 and C30. */
  envelope?: { sha: string; url: string; bytes: Uint8Array };
  /** The document token C28 tests, issued by our own handler for `sha` (the bytes `x`). */
  docToken?: { token: string; x: Uint8Array; sha: string };
  /** The verified document of C44, uploaded and first verified at `uploadedAt` (ms). */
  upload?: { sha: string; url: string; uploadedAt: number; bytes: number };
  /** The index of the identity the sponsor funded in C27. */
  sponsoredIndex?: number;
  /** The demo guest C33 challenged; C43 then admits it with that same challenge. */
  demoGuest?: { person: Person; challenge: Challenge };
  /** The join that admitted the demo guest in C43, kept for its replay. */
  join?: { body: string; txHash: Hex };
}

export class Ctx {
  readonly env: SuiteEnv;
  readonly client: PublicClient;
  readonly wallet: Person;
  readonly people: People;
  readonly lane: WalletLane;
  readonly blobs = new LocalBlobs();
  readonly ips: SourceIps;
  readonly state: SuiteState = {};
  readonly lines: string[] = [];
  readonly startedAt: number;

  private constructor(env: SuiteEnv, client: PublicClient, wallet: Person, startedAt: number) {
    this.env = env;
    this.client = client;
    this.wallet = wallet;
    this.startedAt = startedAt;
    this.people = new People(env.mnemonic, wallet, this.log);
    this.lane = new WalletLane(client, wallet, this.log);
    this.ips = new SourceIps(startedAt);
  }

  static async create(env: SuiteEnv, startedAt: number): Promise<Ctx> {
    return new Ctx(env, evmClient(), await personAt(env.mnemonic, ROLES.wallet.index, "wallet"), startedAt);
  }

  log = (line: string): void => {
    console.log(line);
    this.lines.push(line);
  };

  /** One role, funded and registered as far as its profile says. */
  async need(role: Role): Promise<Person> {
    return this.people.ensure(role);
  }

  /** Gets an attack's shared setup in place: its identities in one batch, then the boards. */
  async prepare(needs: readonly SetupName[] = []): Promise<void> {
    const roles: Role[] = [];
    for (const n of needs) {
      if (n === "boards") roles.push("dana", "eli");
      else roles.push(n);
    }
    const people = await Promise.all(roles.map((r) => this.people.role(r)));
    await this.people.ensureAll(people.map((person, i) => ({ person, profile: ROLES[roles[i]!].profile })));
    if (needs.includes("boards")) await this.boards();
  }

  async affordable(uqor: bigint): Promise<{ ok: boolean; balance: bigint }> {
    const balance = await balanceOf(this.wallet.qor1);
    return { ok: balance - uqor >= WALLET_FLOOR_UQOR, balance };
  }

  /** A deadline DEADLINE_SECONDS after the latest block's timestamp, never the device clock (C2). */
  async deadline(seconds = DEADLINE_SECONDS): Promise<bigint> {
    const block = await this.client.getBlock({ blockTag: "latest" });
    return deadlineFrom(block.timestamp, seconds);
  }

  async boards(): Promise<TestBoards> {
    this.state.boards ??= await this.makeBoards();
    return this.state.boards;
  }

  /** A new board chaired by the wallet, its epoch 0 key sealed to the wallet alone and kept in `keys`. */
  async createBoard(label: string, keys: Map<string, EpochKey> = new Map()): Promise<{ id: bigint; hash: Hex }> {
    const w = this.wallet;
    const boardRef = bytesToHex(newBoardRef());
    const epochKey = newEpochKey();
    const envelope = await sealTo([w.evm], boardRef, 0n, epochKey);
    const envelopeHash = this.blobs.put(envelope);
    const nonce = await createNonceOf(this.client, w.evm);
    const deadline = await this.deadline();
    const paramsHash = paramsCreate({ chair: w.evm, boardRef, envelopeHash, envelopeSize: envelope.length });
    const signature = sign(w, { action: Action.CREATE, boardId: 0n, paramsHash, nonce, deadline });
    const sent = await this.lane.write(calldata.createBoard({ chair: w.evm, boardRef, envelopeHash, envelopeSize: envelope.length, deadline, signature }));
    const id = registryEvents(sent.receipt).find((e) => e.eventName === "BoardCreated")?.args.boardId;
    if (typeof id !== "bigint") throw new Error(`createBoard ${sent.hash} carries no BoardCreated event.`);
    keys.set(`${id}:0`, epochKey);
    this.log(`  board ${label}: id ${id}, created in ${sent.hash} (${sent.receipt.gasUsed} gas)`);
    return { id, hash: sent.hash };
  }

  private async makeBoards(): Promise<TestBoards> {
    const w = this.wallet;
    const dana = await this.need("dana");
    const eli = await this.need("eli");
    const keys = new Map<string, EpochKey>();
    const a = await this.createBoard("A", keys);
    const b = await this.createBoard("B", keys);

    const a0 = await boardAt(this.client, a.id);
    const epoch1 = a0.epoch + 1n;
    const k1 = newEpochKey();
    const env1 = await sealTo([...a0.members, dana.evm], a0.boardRef, epoch1, k1);
    const h1 = this.blobs.put(env1);
    const d1 = await this.deadline();
    const addArgs: AddArgs = {
      boardId: a.id,
      member: dana.evm,
      mode: Mode.ROTATE,
      envelopeHash: h1,
      envelopeSize: env1.length,
      epochAfter: epoch1,
      deadline: d1,
      signature: sign(w, { action: Action.ADD, boardId: a.id, paramsHash: paramsAdd({ member: dana.evm, mode: Mode.ROTATE, envelopeHash: h1, envelopeSize: env1.length, epochAfter: epoch1 }), nonce: a0.nonce, deadline: d1 }),
    };
    const addDana = await this.lane.write(calldata.addMember(addArgs));
    keys.set(`${a.id}:${epoch1}`, k1);
    this.log(`  board A: Dana added by MODE_ROTATE in ${addDana.hash}, epoch ${epoch1}`);

    const a1 = await boardAt(this.client, a.id);
    const env2 = await sealTo([eli.evm], a1.boardRef, a1.epoch, k1);
    const h2 = this.blobs.put(env2);
    const d2 = await this.deadline();
    const eliParams = { member: eli.evm, mode: Mode.SEAL_CURRENT, envelopeHash: h2, envelopeSize: env2.length, epochAfter: a1.epoch };
    const addEli = await this.lane.write(
      calldata.addMember({ boardId: a.id, ...eliParams, deadline: d2, signature: sign(w, { action: Action.ADD, boardId: a.id, paramsHash: paramsAdd(eliParams), nonce: a1.nonce, deadline: d2 }) }),
    );
    this.log(`  board A: Eli added by MODE_SEAL_CURRENT in ${addEli.hash}`);
    return { a: a.id, b: b.id, aCreateHash: a.hash, addDana: { hash: addDana.hash, args: addArgs }, keys };
  }
}
