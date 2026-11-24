import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { EVM_RPC } from "@ava/core";
import { describe, expect, it } from "vitest";
import { BLOB_UPLOAD_API, contentSecurityPolicy, EVM_RPC_ORIGIN, freshNonce } from "./csp";

const NONCE = "AAAAAAAAAAAAAAAAAAAAAAAA";
const BLOB = "https://abc123.public.blob.vercel-storage.com";

function directives(policy: string): Map<string, string[]> {
  const found = new Map<string, string[]>();
  for (const part of policy.split("; ")) {
    const [name, ...sources] = part.split(" ");
    if (name === undefined || found.has(name)) throw new Error(`a directive is repeated or empty: ${part}`);
    found.set(name, sources);
  }
  return found;
}

describe("contentSecurityPolicy", () => {
  const production = contentSecurityPolicy({ nonce: NONCE, blobOrigin: BLOB, dev: false });

  it("is exactly this in production", () => {
    expect(production).toBe(
      [
        "default-src 'none'",
        `script-src 'self' 'nonce-${NONCE}' 'strict-dynamic'`,
        `style-src 'self' 'nonce-${NONCE}'`,
        "style-src-attr 'unsafe-inline'",
        "img-src 'self' blob:",
        "font-src 'self'",
        `connect-src 'self' https://evm-testnet.qore.host ${BLOB} https://vercel.com/api/blob/`,
        "frame-src blob:",
        "manifest-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "upgrade-insecure-requests",
      ].join("; "),
    );
  });

  it("lets no inline or evaluated script run in production, and trusts no host for scripts", () => {
    const script = directives(production).get("script-src") ?? [];
    expect(script).not.toContain("'unsafe-inline'");
    expect(script).not.toContain("'unsafe-eval'");
    expect(script).not.toContain("'wasm-unsafe-eval'");
    expect(script.filter((source) => source.includes(":") && !source.startsWith("'nonce-"))).toEqual([]);
    expect(script).toContain("'strict-dynamic'");
  });

  it("allows inline style only as an attribute, never as an element without the nonce", () => {
    const found = directives(production);
    expect(found.get("style-src")).toEqual(["'self'", `'nonce-${NONCE}'`]);
    expect(found.get("style-src-attr")).toEqual(["'unsafe-inline'"]);
  });

  it("shuts objects, base, forms and framing, and falls back to nothing", () => {
    const found = directives(production);
    for (const name of ["default-src", "object-src", "base-uri", "form-action", "frame-ancestors"]) {
      expect(found.get(name), name).toEqual(["'none'"]);
    }
  });

  it("names the chain endpoint @ava/core reads", () => {
    expect(EVM_RPC_ORIGIN).toBe(new URL(EVM_RPC).origin);
    expect(EVM_RPC).toBe(EVM_RPC_ORIGIN);
  });

  it("reaches the storage API only under its own path", () => {
    expect(BLOB_UPLOAD_API).toBe("https://vercel.com/api/blob/");
    expect(directives(production).get("connect-src")).not.toContain("https://vercel.com");
  });

  it("adds eval, the reload socket and inline style in development only", () => {
    const dev = directives(contentSecurityPolicy({ nonce: NONCE, blobOrigin: BLOB, dev: true }));
    expect(dev.get("script-src")).toEqual(["'self'", `'nonce-${NONCE}'`, "'strict-dynamic'", "'unsafe-eval'"]);
    expect(dev.get("style-src")).toEqual(["'self'", "'unsafe-inline'"]);
    expect(dev.get("connect-src")).toContain("ws:");
    expect(dev.has("upgrade-insecure-requests")).toBe(false);
    expect(directives(production).get("connect-src")).not.toContain("ws:");
  });

  it("leaves out a blob origin that is not a bare https origin", () => {
    const refused = [
      "",
      "http://abc123.public.blob.vercel-storage.com",
      `${BLOB}/`,
      `${BLOB}/document`,
      `${BLOB}; script-src *`,
      `${BLOB} https://evil.example`,
      "*",
      "https://*.example",
      "data:",
    ];
    for (const blobOrigin of refused) {
      const found = directives(contentSecurityPolicy({ nonce: NONCE, blobOrigin, dev: false }));
      expect(found.get("connect-src"), blobOrigin).toEqual(["'self'", EVM_RPC_ORIGIN, BLOB_UPLOAD_API]);
      expect(found.get("script-src"), blobOrigin).toEqual(["'self'", `'nonce-${NONCE}'`, "'strict-dynamic'"]);
    }
  });

  it("refuses a nonce that is short or could end the directive", () => {
    for (const nonce of ["", "abc", "AAAAAAAAAAAAAAAAAAAAA", `${NONCE}' 'unsafe-inline`, `${NONCE}; script-src *`, `${NONCE} `, `'${NONCE}`]) {
      expect(() => contentSecurityPolicy({ nonce, blobOrigin: BLOB, dev: false }), nonce).toThrow("at least 128 bits");
    }
  });
});

describe("freshNonce", () => {
  it("is 24 base64 characters the policy accepts, and never the same twice", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      const nonce = freshNonce();
      expect(nonce).toMatch(/^[A-Za-z0-9+/]{24}$/);
      expect(() => contentSecurityPolicy({ nonce, blobOrigin: BLOB, dev: false })).not.toThrow();
      seen.add(nonce);
    }
    expect(seen.size).toBe(200);
  });
});

// The policy stops an injected script from running. These keep our own code from handing chain data,
// a document or a server's answer to an API that would turn it into markup or code in the first place.
describe("the app's own source", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const banned: [string, RegExp][] = [
    ["dangerouslySetInnerHTML", /dangerouslySetInnerHTML/],
    ["innerHTML or outerHTML", /\.(innerHTML|outerHTML)\b/],
    ["insertAdjacentHTML", /insertAdjacentHTML/],
    ["document.write", /document\.write/],
    ["eval", /\beval\s*\(/],
    ["new Function", /new\s+Function\s*\(/],
    ["srcDoc", /srcDoc/i],
    ["a javascript: address", /javascript:/i],
  ];

  function sources(folder: string): string[] {
    return readdirSync(folder, { withFileTypes: true }).flatMap((entry) => {
      const full = path.join(folder, entry.name);
      if (entry.isDirectory()) return sources(full);
      return /\.(ts|tsx)$/.test(entry.name) && !/\.test\.ts$/.test(entry.name) ? [full] : [];
    });
  }

  it("never builds markup or code from a string", () => {
    const files = ["app", "components", "lib"].flatMap((folder) => sources(path.join(root, folder)));
    expect(files.length).toBeGreaterThan(60);
    const hits = files.flatMap((file) => {
      const text = readFileSync(file, "utf8");
      return banned.filter(([, pattern]) => pattern.test(text)).map(([name]) => `${path.relative(root, file)}: ${name}`);
    });
    expect(hits).toEqual([]);
  });

  it("frames a decrypted pack only with an empty sandbox", () => {
    const frames = ["app", "components"]
      .flatMap((folder) => sources(path.join(root, folder)))
      .flatMap((file) => [...readFileSync(file, "utf8").matchAll(/<iframe\b[^>]*>/g)].map((match) => `${path.relative(root, file)}: ${match[0]}`));
    expect(frames.length).toBeGreaterThan(0);
    for (const frame of frames) expect(frame).toContain('sandbox=""');
  });
});
