# Threat model: the quantum-safe board room

Written 16 Nov 2026 at the architecture gate, before any contract code, from a plain functional
description of the system. Sections A, B and C come from a pre-implementation design review. Section
C is the definition of done: the build is complete only when every invariant in it is shown to hold,
and each one has an attack script in `security/` that tries to break it on testnet.

Platform facts are linked to QoreChain's documentation. This file is kept current as the code lands.

## 0. Design gaps found in review, and how the design answers them

| # | Gap | Answer in the design |
|---|---|---|
| 1 | A relayer window can list at most 16 contracts, so one registry per board breaks at board 16, and an unscoped fallback lets a leaked relayer key call anything | One `BoardRegistry` contract holds every board. The relayer's window lists that one address (C25) |
| 2 | Envelopes are unsigned and only document ciphertext was hash-checked, so a substituted envelope could hand the chair or the bot an attacker-known epoch key | Every envelope's SHA-256 is recorded on chain and checked before it is opened or resealed (C12) |
| 3 | One envelope per epoch cannot represent a member who joins mid-epoch | Append-only list of envelopes per epoch (C6), each checked by the ledger (C39) |
| 4 | The demo bot admitted any address | The guest signs a fresh bot challenge with its own registered ML-DSA key first; one admission per address; demo cap with scheduled guest removal (C33, C34) |
| 5 | Recipient KEM keys reached the chair only through our server | Browsers read KEM keys directly from the public EVM JSON-RPC with `qor_getKEMKey`. Probed live on 16 Nov from two unrelated origins: it answers browsers. Our server is never on that path (C15) |
| 6 | Native-lane registrations need POST to a REST endpoint that sends no CORS headers | The proxy accepts POST only for transaction simulate and broadcast, with a body cap sized to one registration (C22). Probed 16 Nov: REST and the consensus RPC refuse browsers directly |
| 7 | Once-only, rate, budget and nonce decisions need shared durable state | A small shared key-value store; nothing security-relevant lives in process memory (C31) |
| 8 | Public blobs served from the app's origin could run as the app | Blobs come from a separate origin as `application/octet-stream`, attachment, `nosniff`, sandbox CSP (C29) |

Resolved open questions: identities are unified accounts (coin type 60), so the `qor1` and `0x` forms
are the same 20 bytes (C16). A native-lane transaction as the drill proof is still to be confirmed
with the organisers; C36 covers both cases.

## A) App-class risk profile

In security terms this product is nine systems at once:
1. An end-to-end encrypted document store shared by many tenants. Each board is a tenant. Our server, the blob store and the chain are not trusted with confidentiality. Confidentiality rests on keys held in browsers, on how those keys are handed out, and on the order in which on-chain actions land.
2. A browser wallet. Every user's master secret (the 24-word mnemonic, from which all three keys derive) lives in web storage on our origin.
3. A contract whose authority comes from off-chain signatures (meta-transactions). Anyone may submit; only the chair's ML-DSA-87 signature counts.
4. A service that spends its own money for anonymous callers. The relayer pays gas and the sponsor pays QOR.
5. A server-side signing oracle. The demo chair bot signs with a privileged key when an anonymous visitor asks.
6. A request forwarder to a fixed upstream (the REST proxy).
7. A file host with anonymous uploads and public reads (the blob store).
8. A service that renders content controlled by other tenants: decrypted documents, and strings read from chain.
9. A security claim built from public events. The exposure ledger's correctness is itself a product promise.

The categories that typically bite these classes, tied to the flow where each one bites here:

A1. Forged, replayed or reused authorization. Flow: every registry function. Any account may submit, so the chair's signature is the only gate. It fails if the signed message misses a parameter, the nonce, the registry address or the chain id, or if the browser and the contract encode the message differently. It also fails if the bytes could be read as something else the same ML-DSA key signs: the chair's key is its account key, which also signs native-lane transactions. The Q-Day Drill bot will replay every signature it can find on chain.

A2. Misuse of cryptography and key distribution. Flows: add member, remove member, read document. Four weak points:
- The chair seals to ML-KEM keys it reads from somewhere.
- Envelopes are unsigned and fetched from a public store ([QoreSeal docs](https://docs.qorechain.io/developer-tools/qoreseal)).
- Several chair devices can encrypt under one epoch key, so AES-GCM nonces can repeat.
- AAD and purpose strings built in two places can differ.
Each one either gives an outsider the epoch key or breaks decryption.

A3. Races and ordering (the check happens at one time, the use at another). Flows: a document post and a member removal racing through the relayer; two chair sessions rotating from different views of the member set; parallel guest joins; parallel sponsor requests for one address. On a board, ordering protects confidentiality: a document that lands after a removal, under the old epoch key, is readable by the director who was removed.

A4. Script injection and key theft in the browser (cross-site scripting). Flows: open a document, list my boards, the exposure ledger, blob downloads. Any script on our origin can read every stored identity and capture the passphrase as it is typed. Inputs that reach the page: decrypted documents written by another tenant's chair, chain strings (URIs, ids, event data), proxy responses, and blobs if they are served from our origin.

A5. Server-side request forgery and open proxy. Flow: the REST proxy. A path joined onto a base URL can change the host (`//evil.example/` or a full URL), and a redirect the server follows can land anywhere the server can reach. Separately, the public REST rate-limits each IP. Every user shares our server's quota, so one heavy client can use it up for everyone.

A6. Draining money and resources. Flows: sponsor, relay, upload, guest join. Each anonymous request spends something: QOR, gas, window slots that renew themselves, storage, member slots, envelope bytes (1,632 per recipient in mlkem mode).

A7. Confused deputy and signing oracle. Flows: the demo chair bot and the relayer. The bot signs with a key that becomes the demo chair account's only protection once the drill key is published. The relayer submits to whatever target the request names.

A8. Handling of secrets. Flows: relayer, sponsor, bot. The server holds both keys of two funded accounts and the ML-DSA key of a third. In Next.js, a value under a `NEXT_PUBLIC_` name, or one passed to a client component, ships to every visitor.

A9. Unrestricted upload. Flow: blob upload. Naming blobs by their hash only helps if the server computes the hash. Public read makes the store a free host for anything.

A10. Integrity of a derived claim. Flow: the exposure ledger. It understates exposure if it is built from timestamps instead of epoch grants, if it reads a look-alike registry or a log read that was cut short, or if it trusts events about who an envelope was sealed to without checking the envelope.

A11. Identity confusion. Flows: invite and add, sponsor, guest join, KEM lookup. One account has a `qor1` form and a `0x` form, and the KEM route accepts both. If two parts of the system convert between them differently, the chair adds one account and seals to another.

A12. Contract basics. Two apply. Gas and storage griefing (member set size, URI length). An inactive precompile that answers with empty data instead of reverting ([EVM precompiles](https://docs.qorechain.io/developer-guide/evm-precompiles)). Front-running applies only as copying: a copied relayed action has the effect the chair intended, and the relayer pays for its own reverted duplicate.

Do not apply, and why:
- SQL or NoSQL injection: no database is described. If one is added for the shared state in C31, its queries are parameterized.
- OS command injection, server-side template injection, XML external entities: no shell, no server-rendered user templates, no XML.
- Session hijacking and cross-site request forgery: there are no cookies or sessions, and every authority is a signature over one specific action. Cross-origin access still matters (C23), because any web page could make its visitors' browsers call an endpoint that spends money.
- Reading someone else's object by guessing its id: everything stored is public by design and protected by encryption, so fetching another tenant's object yields only ciphertext.
- Reentrancy, price-oracle manipulation, flash loans, token approval abuse: the contracts hold no value, price nothing, send nothing, and call nothing untrusted. Their only outside calls are static calls to the two PQC precompiles.
- DNS rebinding: the proxy's host is one fixed HTTPS name and no attacker-chosen name is ever resolved, as long as C22 holds.

## B) Threat model

### Trust boundaries
- T1. Browser to our endpoints (relay, sponsor, proxy, upload, guest join): every field, header and request rate is untrusted.
- T2. Any EVM sender to the registry: calldata is untrusted. Authority comes only from pqcVerify against the chair's registered key.
- T3. Registry to the PQC precompiles: trusted chain code, but an inactive precompile returns success with empty data.
- T4. Our server to the public REST and EVM RPC: trusted for chain state over HTTPS. For native-lane reads that browsers cannot make directly, our server sits between that state and the browser.
- T5. Blob store to readers (browsers and the bot): bytes are untrusted until their SHA-256 matches the on-chain record.
- T6. Chain state to the app: trusted as a record of what happened, but much of it is written by attackers. Anyone can deploy a contract with our ABI and events, register a KEM key, create a board and add any address to it.
- T7. One tenant to another: a chair's signed URIs, sizes, ids and document plaintext are untrusted for that board's directors. Those directors may sit on other boards whose keys live in the same browser storage.
- T8. Browser storage to the app: the stored identity blob is read back and must pass authentication when it is decrypted.
- T9. Out-of-band channels: the director's address passed to the chair, invite links, board addresses in app URLs.
- T10. Server secrets to anything that leaves the server: responses, logs, error pages, client bundles, server-component payloads.
- T11. The Q-Day Drill: from 18 Nov an outside party holds the demo chair's secp256k1 key, and after the drill so does everyone.
- T12. Relay responses to the browser: a transaction hash is a claim, not a result.
- T13. npm dependencies to the browser bundle: every package runs on our origin, next to the keys.

### Attacker-controlled inputs
Direct:
- Relay: the action type, the target, every parameter (member address, envelope hash, URI, document id, epoch, ciphertext hash, byte size, add mode), the nonce, the deadline, the signature bytes, the body size, the request rate, and headers such as X-Forwarded-For.
- Sponsor: the address string (prefix, checksum, case, length, 0x or qor1, contract or module addresses), how often it is sent, and how many different addresses are used.
- Proxy: path, query string, percent-encoding, dot segments, method, headers.
- Upload: the bytes, their length, the declared content type, any key or name the client suggests.
- Guest join: the guest address, any proof offered, the request rate, the number of identities.
- App URLs and invite links: registry addresses, board ids and chair addresses.

Indirect:
- Upstream REST and RPC responses: status, headers, redirects, body size, latency, `found` flags, key bytes, the address echoed in a KEM record, and log pagination that stops early.
- Chain content written by others: look-alike registries and their events, the KEM keys members choose, PQ key records, transaction memos, and any board names or labels if they are added later.
- Blob contents as served, and whatever an on-chain URI points to.
- Chair-signed values as a director sees them: URI, byte size, id, and the decrypted document with its declared name and type.
- Values stored and read back later: the encrypted identity in browser storage, cached epoch keys in the browser and in the bot, the server's records of sponsored addresses, rate counters, nonce queues.
- Time: the block timestamp (set by validators) and the browser clock used for deadlines.
- Keys others hold: from 18 Nov the drill bot can make valid secp256k1 signatures for the demo chair account, and after the drill anyone can.
- The mempool: relayed actions can be seen and copied before they land.

### Privileged position and assets
- The relayer account's two keys, its QOR, and its open EVM window. The window is a budget of transactions and QOR that its classical key can spend with no further post-quantum signature.
- The sponsor account's two keys and its QOR.
- The demo chair's ML-DSA-87 secret key, plus its ML-KEM key or cached epoch keys. Once the drill publishes the secp256k1 key, this one server secret is the demo chair account's entire protection. With both keys, an attacker can sign native-lane transactions, open windows and rotate the key.
- Our origin: every user's encrypted identity sits there and every passphrase is typed there. Script running on our origin reaches every board those users belong to.
- Our server's network position: its IP's quota at the public REST, and anything its runtime can reach.
- The blob store's write path, and the domain it serves from.
- The power to spend money: sponsor transfers, relayer gas, automatic window renewal.
- The registry: the source of truth for "is this a real board".
- Within each board: the chair's ML-DSA key, which controls membership and epochs, and every director's browser, which holds every epoch key sealed to that director.

### Attacker goals
- G1. Read documents of a board they are not on, or were removed from. Flows:
  - (a) swap a member's ML-KEM key during add or remove member;
  - (b) swap the current epoch envelope so the chair's browser or the bot encrypts or reseals under a key the attacker knows;
  - (c) run script on our origin through a malicious document, a chain string or a blob, and read the stored identity;
  - (d) get a document posted under epoch E to land after a removal that moved the board to E+1;
  - (e) race two rotations so the newer epoch is sealed from a stale member list that still includes the removed director.
- G2. Act as the chair. Flows: replay an action that already landed; reuse a signature on another board, another chain or after a redeploy; find a parameter the signature does not cover; get the chair's key to sign bytes that are also a valid app action, or the reverse; make the demo bot sign for them; steal the server's demo ML-DSA key and pair it with the published drill key; find any endpoint or contract role that trusts a secp256k1 signature or msg.sender.
- G3. Spend our money. Flows: script thousands of identities against the sponsor; send the relayer actions that will revert, or copy its pending actions so its own copies revert; push actions with high gas; ride the automatic window renewal; on 18 Nov, use the drill key inside any window the demo chair account has open.
- G4. Make the exposure ledger lie. Flows: deploy a look-alike registry; cut a log read short; exploit a calculation by timestamp that misses seal-current grants; seal an epoch key to a non-member in an envelope the ledger never inspects; add strangers to the demo board so the ledger says they read its documents.
- G5. Take the demo down while judges are using it. Flows: mass guest joins that pass the member cap, QoreSeal's 1,024-recipient cap or the upload cap; contention in the bot's and the relayer's nonce queues; using up our server's upstream REST quota through the proxy; filling the blob store.

## C) Defensive-programming standards (the definition of done)

Each invariant below is an outcome. Any change that touches an area names the invariants it carries,
and review checks the file and function that upholds each one. The attack scripts in `security/` try
to break each one on testnet and save the output.

Note on the chosen shape: the review was written against a factory with one registry per board. The
design now uses one `BoardRegistry` for every board (gap 1). Read "factory" below as that registry,
"isRegistry" as "the board id exists in it", and "registry address" as "registry address plus board id".

### C.1 Board authority
- C1. Only the chair's current, possession-proven ML-DSA-87 key can change a board. Every state-changing function succeeds only when pqcVerify returns true for a message the contract builds itself. The key comes from pqcKeyStatus(chair) and must have registered true, algorithmId 1, possessionProven true, and length 2,592 bytes. msg.sender grants nothing. An inactive precompile, empty return data or a decode failure reverts. Proof: call each function with no signature, with another account's valid signature, and with a chair whose possessionProven is false. All revert.
- C2. One signature authorizes one action, once, in one place.
  - The signed message covers: an app domain tag, block.chainid, the contract's own address, the board id, the action code, every parameter that reaches storage or an event (including the add mode and the expected new epoch number), the nonce and the deadline.
  - Nonce: one per board, shared by every action type (per chair for board creation). Strictly sequential: it must equal the stored value, then it goes up by one.
  - Deadline: in seconds, checked against block.timestamp, and never more than one hour ahead, so no signature outlives a testnet reset that redeploys at the same address.
  - Replay protection never keys on signature bytes, because ML-DSA allows many valid signatures for one message.
  - Proof: replay a landed action; submit board A's signature to board B; change each parameter in turn; use an expired deadline and one too far ahead. All revert.
- C3. App signatures can never be anything else. The domain tag's first character is not `q`. So no app message can begin with any QoreChain reserved prefix (`qorechain-pqc-hybrid-v2`, `qorechain-pqc-pop-v1|`, `qorechain-pqc-rotate-v1|`, `qorechain:pqc:recovery:v1`, `qorechain-siwq-v1|`, `qorechain-msg-v1|`, `qorechain-svm-auth-v2`, or any future one starting with `qorechain`), and nothing signed under those prefixes can be an app message.
- C4. The browser and the contract sign and verify the same bytes. One specification builds the message:
  - abi.encode, never abi.encodePacked over two or more variable-length values;
  - parameters committed as a hash, so the message has a fixed length;
  - pure ML-DSA-87 with an empty context and no prehash, which is how pqcVerify checks it;
  - total pqcVerify input under the 16,384-byte precompile limit ([EVM window reference](https://docs.qorechain.io/developer-guide/evm-window-reference)).
  Proof: one shared test vector that the Solidity tests and the TypeScript tests both produce, byte for byte.
- C5. A document is always posted under the epoch that is current when it lands. postDocument reverts unless its signed epoch equals the board's epoch at execution. removeMember and rotateEpoch set the epoch to exactly the old value plus one, and the signature names that number. Proof: sign postDocument for epoch E, land a removeMember first, then submit the postDocument. It reverts.
- C6. History is append-only. A document id is assigned once (by the registry, or checked as unused) and its record never changes. Every envelope that ever granted an epoch's key stays on chain in an append-only list for that epoch: a seal-current addMember appends and never replaces. Every change emits an event with enough fields (member, epoch, envelope hash, mode, nonce) to rebuild the full state from events alone.
- C7. A board is always well formed. The chair is always a member and cannot be removed. Members are unique. The member count stays between 1 and MAX_MEMBERS, which is at most QoreSeal's 1,024-recipient cap and low enough to keep every function well inside the gas limit. Adding an existing member or removing a non-member reverts. The target of transferChair must be a current member whose key is possession-proven at that moment.
- C8. Storage and gas are bounded. Every variable-length parameter has an on-chain length cap, and no function loops over a set without a fixed upper bound.
- C9. Real boards are the ones the registry made. The registry answers whether a board id exists. Every client and server treats any other contract address or board id as unknown, whatever its ABI and events look like.
- C10. There is nothing to drain and no classical owner. The contracts accept no value (non-payable, no receive or fallback function) and hold no tokens. No role is checked against msg.sender: no Ownable owner, no admin, no upgrade key held by a secp256k1 account. If anything is upgradeable, upgrades go through the same ML-DSA-signed path.

### C.2 Encryption and key distribution
- C11. Epoch keys are fresh. Each one is 32 bytes from the platform's cryptographic random source, new for every epoch, never derived from an earlier key, and never shared between boards.
- C12. Nothing is used until its hash matches the chain. No envelope is opened, no epoch key is used to encrypt or reseal, and no ciphertext is decrypted unless the SHA-256 of the exact bytes received equals the on-chain record for that board and that epoch or document.
  - The hash is taken over raw bytes, in the same form that was uploaded and recorded. Never the `qoreseal:` text form, never a re-encoding.
  - The epoch number inside the opened key payload must equal the expected epoch.
  - This applies to the chair's browser and to the bot, not only to readers.
- C13. Every ciphertext is bound to its place.
  - QoreSeal's chainId is `qorechain-diana`. Its purpose string is built by one function from the board's place (SHA-256 of the registry address and the board's random boardRef) and the epoch number, within QoreSeal's allowed characters and 128-character limit.
  - The document AAD is one fixed binary layout (place, epoch, docRef), built by one function for both encryption and decryption. The board's sequential id is never used in encryption, because the first envelope is sealed before the id exists.
  - An envelope or ciphertext moved to another board, epoch or document fails to open. Proof: move each one across boards and epochs; every attempt gives DECRYPTION_FAILED or a GCM failure.
- C14. No key and nonce pair is ever used twice. Each document is encrypted under its own key, derived with HKDF from the epoch key with the document's random docRef as salt (because several chair devices may share one epoch key), with a fresh random 96-bit GCM nonce.
- C15. Every recipient key is genuine. An ML-KEM key is used for sealing only if all of these hold:
  - it is the key registered for exactly the 20-byte address being sealed to (the address in the response, decoded by the C16 codec, equals the address requested);
  - its algorithm id is 2, it is 1,568 bytes, and it passes validateMlkemPublicKey;
  - it did not come from a server we run. The browser reads it from the chain with `qor_getKEMKey` on the public EVM JSON-RPC ([key features](https://docs.qorechain.io/introduction/key-features)), which answers browsers directly (probed 16 Nov).
  A `found: false`, a mismatch or a timeout stops the seal.
- C16. One account, one form. A member is a 20-byte value. Addresses that arrive in a request are decoded strictly (qor1 with a valid checksum, or 0x in exact EIP-55 form); the lenient decoder that also accepts all-lowercase 0x is used only for values read from the chain. Every component (browser, relayer, bot, sponsor, ledger, KEM lookup, pqcKeyStatus) converts between `qor1` and `0x` with one shared function and compares bytes, never strings. Anything that does not decode with a valid checksum is rejected. Identities are unified accounts (coin type 60), so the address a new identity shows the chair is the one whose 20 bytes own its ML-DSA and ML-KEM registrations. Proof: onboard an identity, add it by its `0x` form, and confirm that pqcKeyStatus and the KEM lookup both find it.
- C17. A rotation is sealed to exactly the members the registry holds once it lands. The browser reads the member set and the nonce from the same block and signs that nonce. Because every action moves the nonce (C2), a rotation built from a stale view reverts instead of reaching a removed director. Proof: two chair sessions remove two different members at the same time. The second one reverts, and the first removed member's key cannot open the new epoch's envelope (NOT_A_RECIPIENT).

### C.3 Browser keys and rendering
- C18. Secrets stay in the browser that made them. The mnemonic, the ML-DSA and ML-KEM secret keys, epoch keys and the passphrase are never sent to any server, never logged, never put in a URL or an analytics event, and never written to storage unencrypted. The stored identity is encrypted with AES-GCM under a key from a slow password KDF with a fixed minimum cost (PBKDF2-SHA-256 at 600,000 iterations or more, or scrypt, or Argon2id), a random salt and a minimum passphrase length. A failed or malformed decryption leaves the wallet locked. There is no fallback.
- C19. No script but ours runs on the app's origin. The Content-Security-Policy is nonce-based, with no unsafe-inline or unsafe-eval, and sets object-src none, base-uri none and frame-ancestors none. There is no dangerouslySetInnerHTML, or anything like it, with chain data, document data or upstream responses. Every chain string, id, URI and error message is rendered as text.
- C20. A document from one board can never reach another board's keys. Decrypted content is never active content on the app's origin: it is never rendered there as HTML, SVG or XML, and never opened as a same-origin `blob:` URL of an active type. Previews run only in a sandboxed frame without allow-same-origin, for a short allowlist of types detected from the bytes (not from the declared type). Everything else downloads under a cleaned filename: no control characters, no bidirectional characters, no path parts. Proof: a chair posts an HTML file and an SVG that contain script. Opening them in a director's browser runs nothing on the app's origin.
- C21. Boards from strangers do nothing on their own. A board the user did not create or accept is labelled with its chair address and board id, and nothing in it is fetched or rendered until the user opens it.

### C.4 Server endpoints
- C22. The proxy reaches only the chain's public REST, and only the parts of it the app needs.
  - The outgoing URL is parsed into a URL object, and that same object is the one sent. Its origin must be exactly `https://api-testnet.qore.host`.
  - The path must match one of the routes the app uses. Each path parameter is decoded by its own codec (address, hash, upgrade name), and query parameters are limited to the ones each route needs, with numeric caps.
  - Redirects are refused, not followed. No client header is forwarded.
  - The response goes back only as JSON, under our own `Content-Type: application/json` and `X-Content-Type-Options: nosniff`. Upstream headers are dropped, the body is capped, and there is a timeout.
  - POST is accepted only for transaction simulate and broadcast, with a body cap sized to one hybrid-signed registration.
  - Proof: `//evil.example/`, a full URL, `..%2f`, a double-encoded path and an upstream redirect all fail.
- C23. Our endpoints serve our app, not the internet. There is no wildcard CORS. Rate limits apply per client IP, as reported by the hosting platform (never a header the client supplies), and in total. They are set below the upstream per-IP budget, so no single client can spend that budget for everyone.
- C24. The relayer pays only for valid actions on our own contract.
  - It builds the calldata itself from typed parameters.
  - The target is the one registry address, a build-time constant.
  - It broadcasts only after an eth_call of the exact transaction succeeds.
  - Gas limit and fee cap are fixed ceilings per action type.
  - It rate-limits per chair and per board. Past a daily spending ceiling it refuses actions and stops renewing its window.
  - It orders its own nonces in shared state, and re-signs anything signed before a window renewal (opening a window moves the account nonce, [EVM window reference](https://docs.qorechain.io/developer-guide/evm-window-reference)).
- C25. The relayer's window stays narrow. It is never unscoped in production. allowed_targets holds only the registry address. max_value is sized with evmWindowCost for a set number of actions, and renewal keeps the same scope. Proof: with only the relayer's secp256k1 key, try a QOR transfer, a call to any other contract and a contract creation. All are refused, and calls to our own contract carry no authority.
- C26. A relay response is only a claim. The browser marks an action done only when the receipt shows success and the registry event with the expected nonce is on chain. Until then, or until the deadline passes, the screen says pending.
- C27. The sponsor funds each new identity once, within a budget, with no more than it needs.
  - The address is decoded by the C16 codec.
  - The amount is a server constant, sized to the two registrations. A new account must register its key first ([first transaction](https://docs.qorechain.io/getting-started/first-transaction)), so a scripted identity is left with almost nothing.
  - Eligibility is read from chain: no registered PQ key, no balance.
  - A once-per-address record is written atomically to shared durable state before the send.
  - Per-IP and daily totals are capped, and sends are queued one at a time.
- C28. Every stored blob's name is the SHA-256 of the bytes the store actually holds, checked by the server, never a name the client chose. Envelopes are uploaded through the server, which hashes what it receives. Documents (too large for the host's request limit) go from the browser straight to the store under a short-lived token that allows exactly one pathname, `document/<sha256>`, octet-stream only, within the size cap, never overwriting; the server then re-reads what the store holds, hashes it, and deletes it on any mismatch. An existing name is never overwritten. Byte caps are enforced while reading, not after buffering. Per-IP and total quotas apply. Unverified documents older than an hour are deleted; a document that was once verified is never deleted by a later check (C44).
- C29. Blobs are served as plain bytes that cannot run. They come from a separate origin (another registrable domain, never the app's), as `application/octet-stream`, with `Content-Disposition: attachment` and `nosniff`. Checked live on 17 Nov: the store serves exactly these, plus `Content-Security-Policy: default-src 'none'`. It does not add a `sandbox` directive; the separate origin, attachment, octet-stream and nosniff together keep anything uploaded from running as the app, and the app never navigates to a blob, it only fetches bytes.
- C30. Readers fetch only the expected location, and only as much as expected. The browser builds the fetch URL from the on-chain hash and the configured blob origin. An on-chain URI is used only if it equals that form when parsed by the same URL parser. Downloads stop at the on-chain byte size for documents, and at the largest possible envelope (56 + 1,632 x MAX_MEMBERS + payload) for envelopes. The size check comes before hashing.
- C31. Every once-only, rate, budget and nonce decision lives in shared durable state or on chain, never in process memory. Serverless instances do not share memory, and a restart wipes it. Window renewal and the bot's queue run under a lock in that shared state, or on a schedule that exists between requests.
- C32. No secret reaches a visitor. Server keys are read only in server-only modules. They are never under a `NEXT_PUBLIC_` name, never passed to a client component, and never appear in an error page, a response or a log line. Proof: build the app, then grep the client bundles, the rendered HTML and the server-component payload for every key and address that must stay private.

### C.5 Demo chair bot and the drill account
- C33. The bot is not a signing oracle. It builds every message itself and signs only addMember (admitting one guest) and removeMember (its scheduled guest removal), only for the configured demo board. It signs only after that guest has signed a fresh challenge the bot issued, using the guest's registered, possession-proven ML-DSA key. The challenge is bound to the demo board, a bot nonce and an expiry, under the C3 tag. The bot never signs bytes that came in a request.
- C34. Admission is bounded. One admission per address. Per-IP and total rate limits. A demo member cap below MAX_MEMBERS, with a scheduled rotation that removes guests, so scripted joins can never reach QoreSeal's 1,024-recipient cap or the upload cap. Joins queue one at a time, because the board nonce is sequential.
- C35. The bot reseals only what it has checked. It uses an epoch key only after the C12 check, and seals only to the key that C15 and C16 return for the address being admitted.
- C36. The drill key buys nothing.
  - The demo chair account holds no open EVM window. If the drill's proof must be an EVM transaction, the account opens one window (one transaction, a few blocks, scoped to one of our contracts, max_value from evmWindowCost), sends at once, and closes it.
  - No endpoint or contract accepts a secp256k1 signature, a Sign-In-With-Ethereum login or msg.sender as authority.
  - The demo chair's ML-DSA and ML-KEM keys cannot be derived from the secp256k1 key handed to the organisers (they come from the mnemonic, which never leaves our server).
  - Relayer, sponsor and demo chair are three separate accounts, each holding only what its job needs.
  - Proof: on testnet, run the drill's list of moves with that key (native transfer, window open, EVM transfer, approval, and every contract function with replayed signatures), and save each refusal.
- C37. The demo chair's ML-DSA key is protected as the whole account, because it is. It lives only in server secrets and is loaded only by the C33 code path. A written rotation step (MsgRotatePQCKey, then confirm with pqcKeyStatus) exists for the day it leaks.

### C.6 Exposure ledger
- C38. The ledger never understates exposure.
  - It works from epoch grants, not timestamps. A person is exposed to every document of every epoch whose key was ever sealed to them, including documents posted earlier in an epoch they joined by seal-current.
  - It reads only the deployed registry, from the public EVM JSON-RPC, which answers browsers.
  - Any log read that fails, times out or is cut short shows "incomplete" instead of a shorter list.
  - The member set it rebuilds from events must match the registry's view functions at the block it read. A mismatch shows "incomplete".
- C39. The ledger checks the envelopes, not only the events. For each envelope on chain, it compares the recipient count in the header with the number of members whose ML-KEM keys match a recipient hint. Anyone holding a public key can run that test ([QoreSeal docs](https://docs.qorechain.io/developer-tools/qoreseal)). Any extra entry is shown as an unknown reader. Envelopes are therefore never sealed with `anonymous: true`. An envelope the ledger cannot check (for example, a member has since replaced their key) is shown as unverified, never as clean.

### C.6b Added after the backend review (17 Nov)
- C40. Only work that passes a signature check consumes a signed party's budget. The relay runs its exact pre-flight before any per-chair, per-board or valid-action counter; requests that fail it count only against per-IP and a separate rejected total, so junk cannot starve a chair's real actions.
- C41. A fresh judge can always join the demo board: when it is full, the oldest guest is removed first.
- C42. No member's key state can block the removal of another member. A guest whose encryption key is missing, changed or invalid becomes the next guest removed; a problem with the chair's or a seeded director's key raises an alert and removes no one.
- C43. A guest challenge is consumed only by a join that carries a valid signature over it, and at most once.
- C44. A verified document blob is never deleted by a later read. Every envelope blob is referenced by an EnvelopeGranted event within two hours or swept.
- Accepted, not fixed: boardRef squatting. Board refs are unique per registry, so someone watching pending transactions could create a board with a victim's pending boardRef first. The victim's creation fails with BoardRefUsed and the app retries with a new boardRef and a resealed envelope. No board's confidentiality is affected, because a place is never shared between two boards.

### C.7 The five general standards, applied here

1. Primitives over lists. Each check says what it covers and what it does not.
- "Is this a real board" is answered by the registry's own record. It covers every board ever made with nothing to maintain. It does not cover a registry we did not deploy, so the registry address is a constant fixed at build time.
- "Is this action valid" is answered by an eth_call of the exact transaction. The contract is the check, so there is no second signature checker that can drift from it. It does not cover state changing between the call and inclusion, which only makes the transaction revert.
- "Where does the proxy go" is answered by origin equality on the parsed URL, which covers every host trick at once. The route list next to it is an allowlist that fails closed: a missing entry breaks a feature and never opens a hole. The list exists to stop the proxy being a free general-purpose proxy, not to stop request forgery.
- "Is this an address" is answered by the bech32 and hex codec with checksum, never a regular expression. It does not cover a valid address belonging to the wrong person (C21, non-goals).
- "Is this a KEM key" is answered by QoreSeal's validateMlkemPublicKey, the same check the chain applies. It does not cover a valid key that belongs to someone else (C15).
- "Could this signature be something else" is answered by a tag whose first character is not `q` (C3). It covers every reserved prefix that exists today and any future one starting with `qorechain`. It does not cover a future reserved prefix that starts with our tag's first character.
- "What can we preview" is answered by an allowlist of types detected from the bytes. We never keep a list of dangerous types.

2. Normalize before you compare.
- Addresses: one codec, compared as 20 bytes (C16).
- Signed messages: one encoder, with a shared test vector (C4).
- Hashes: SHA-256 over raw bytes in the upload, record and read paths, compared as bytes32, never as hex strings that might differ in case.
- URLs: the URL object that was checked is the one that is fetched (C22, C30).
- Purpose and AAD: one builder each (C13).
- Chain identity: EVM chain id 9800 in signed messages and `qorechain-diana` in QoreSeal, both from one module of constants.
- Time: deadlines in seconds, taken from the latest block's timestamp, not from the browser clock.

3. Validate outputs like inputs.
- Proxy responses are checked and relabelled before they reach the browser (C22).
- The URI the upload endpoint returns is checked against the expected form before the chair signs it, because a signed URI stays on chain for good.
- A relay transaction hash is confirmed on chain before it counts (C26).
- Blob bytes are hash-checked before use (C12, C30).
- Chain strings and decrypted documents are rendered as plain text or inside a sandbox (C19, C20).
- The bot's addMember is a write to the chain and gets the same checks as a chair's (C33 to C35).
- The ledger is a security claim shown to judges, so it says "incomplete" rather than show a partial answer (C38, C39).
- Upstream error text is never echoed into HTML, and log lines never carry secrets (C32).

4. Fail closed.
- Contract: empty precompile data, pqcVerify false, possessionProven false, wrong epoch, used nonce, expired or too-distant deadline: revert.
- Browser: KEM `found: false`, any hash mismatch, an envelope parse error, a GCM failure, an unexpected epoch payload: stop and show the error, never partial plaintext.
- Server: a failed simulation, a reached budget, a failed window renewal, any failed lookup in the sponsor: refuse.
- Limits, all explicit: upload byte cap, relay body cap, proxy response cap and timeout, RPC timeouts, envelope cap, MAX_MEMBERS, URI length cap, deadlines at most one hour ahead, a maximum page count when reading logs.
- Defaults: narrow windows, no CORS, blobs that cannot run, separate accounts with small balances, and `mlkem` mode only as an explicit choice.

5. Non-goals: what this design does not defend against.
- The chair, or anyone holding the chair's key or device. The chair can read everything and seal the epoch key to anyone. The contract cannot see who an envelope is sealed to; C39 catches extra recipients only in recorded envelopes.
- What a removed director already received. They keep every epoch key they were given and can read those documents forever, because the ciphertexts are public. Removal protects only documents posted afterwards. The exposure ledger exists to show this honestly.
- Metadata. Board membership (as addresses), document counts, sizes, timing, epochs and removals are all public on chain.
- A director's own compromise: malware, a hostile browser extension, physical access, a weak passphrase, or a lost mnemonic. There is no recovery; the data is gone.
- A compromised npm dependency or build pipeline. Pinned versions and a lockfile reduce this risk; they do not remove it.
- A flaw in QoreSeal 0.1.0 (pre-1.0, its construction is pending external review) or in ML-KEM-1024. `mlkem` mode has no classical X25519 layer to fall back on.
- Censorship by the relayer. It cannot forge, and the nonce stops it reordering, but it can delay or drop an action. A chair can always submit the signed action from any funded account instead.
- Copying of relayed actions from the mempool. The copy has the effect the chair intended; the relayer pays for its own reverted duplicate, and rate limits bound how often.
- Scripted identities draining the sponsor and the relayer, up to their daily ceilings.
- The demo board's documents. They are public by design: every guest receives the key, and the bot's server holds it.
- The chain itself. Its PQ key registry, KEM registry and precompiles are trusted. Board authority follows the chair account's current registered key, so anything the chain allows to replace that key moves the board along with it.
- The out-of-band address exchange. If a director's address is swapped on its way to the chair, the wrong person is invited.
- Old signatures after a testnet reset. Only the one-hour deadline limits them.
