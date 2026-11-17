/**
 * Writes one JSON line for a security-relevant event: a refusal, a rate-limit hit, a store failure.
 * Callers pass short codes and numbers this package chose. Never a request body, a header value,
 * an upstream error text or a secret (threat model C32).
 */
export function logEvent(event: string, fields: Record<string, string | number | boolean> = {}): void {
  console.warn(JSON.stringify({ event, ...fields }));
}
