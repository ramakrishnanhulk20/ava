import type { GuestSession } from "./identity";

// The identity a visitor has opened, kept in this page's memory so that moving between the board
// room's screens does not ask for the passphrase again. It is never written anywhere: a reload, a
// new tab or closing the page drops it, and the passphrase is asked for again (threat model C18).
let held: GuestSession | undefined;

export function heldSession(): GuestSession | undefined {
  return held;
}

export function holdSession(session: GuestSession | undefined): void {
  held = session;
}
