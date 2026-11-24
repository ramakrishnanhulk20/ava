// FNV-1a folds the seed text into a 32-bit number, then xorshift32 walks from it. Both are
// plain integer maths, so the server and the browser print the same rows.
function seedFrom(text: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash === 0 ? 0x9e3779b9 : hash;
}

function* xorshift32(seed: number): Generator<number, never, void> {
  let state = seed >>> 0;
  while (true) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    yield state;
  }
}

/** Rows of fake ciphertext for the sealed pack: `cols` lowercase hex characters, grouped in pairs. */
export function hexRows(seed: string, rows: number, cols: number): string[] {
  const next = xorshift32(seedFrom(seed));
  const out: string[] = [];
  for (let r = 0; r < rows; r += 1) {
    const pairs: string[] = [];
    for (let c = 0; c < cols; c += 2) {
      const left = (next.next().value >>> 8) & 15;
      const right = c + 1 < cols ? (next.next().value >>> 8) & 15 : null;
      pairs.push(left.toString(16) + (right === null ? "" : right.toString(16)));
    }
    out.push(pairs.join(" "));
  }
  return out;
}

/** One row of random hex for the scramble in the "how it works" visual. Random on purpose, so it only ever runs in the browser after load. */
export function randomHexRow(cols: number): string {
  const pairs: string[] = [];
  for (let c = 0; c < cols; c += 2) {
    const left = Math.floor(Math.random() * 16).toString(16);
    const right = c + 1 < cols ? Math.floor(Math.random() * 16).toString(16) : "";
    pairs.push(left + right);
  }
  return pairs.join(" ");
}
