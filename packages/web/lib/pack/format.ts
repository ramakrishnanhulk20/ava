/**
 * What a pack is once it is decrypted (docs/spec/pack.md). The chain stores a pack's hash, size,
 * epoch and time and nothing else, so a file's name travels inside the encrypted bytes, in a small
 * container: 8 magic bytes, a 2-byte big-endian header length, a JSON header `{"name": "..."}`,
 * then the file's own bytes. Bytes with no container are a pack with no name, which is what the
 * demo board's plain-text packs are.
 */

/** "AVAPACK" and the format version, 1. */
const MAGIC = Uint8Array.from([0x41, 0x56, 0x41, 0x50, 0x41, 0x43, 0x4b, 0x01]);
const LENGTH_BYTES = 2;
/** The most a stored name may take, in UTF-8 bytes. */
export const MAX_NAME_BYTES = 200;
/** The header is `{"name":"..."}` with the name JSON-escaped; this bounds it with room to spare. */
const MAX_HEADER_BYTES = 1_300;
/** The bytes the container adds before the header: the magic and the header's length. */
export const CONTAINER_FIXED_BYTES = MAGIC.length + LENGTH_BYTES;

/** A pack that claims to be a container and cannot be read as one. Nothing is guessed from it. */
export class PackFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PackFormatError";
  }
}

// Controls (C0, DEL, C1), the direction marks and isolates that can make a name read backwards, and the zero-width marks.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f؜​-‏‪-‮⁠-⁩﻿]/gu;
const RESERVED = /[<>:"|?*]/gu;

function clip(name: string): string {
  const encoder = new TextEncoder();
  if (encoder.encode(name).length <= MAX_NAME_BYTES) return name;
  const dot = name.lastIndexOf(".");
  const extension = dot > 0 && name.length - dot <= 12 ? name.slice(dot) : "";
  let stem = [...(extension === "" ? name : name.slice(0, dot))];
  while (stem.length > 1 && encoder.encode(stem.join("") + extension).length > MAX_NAME_BYTES) stem = stem.slice(0, -1);
  return stem.join("") + extension;
}

/**
 * The name a download is saved under (threat model C20): the last path part only, with no control
 * characters, no direction marks, nothing a file system or a shell reads specially, no leading
 * dots, and at most MAX_NAME_BYTES of UTF-8. Letters of any script are kept.
 *
 * @param fallback Used when nothing usable is left, for example "pack-3".
 */
export function cleanFilename(name: string | undefined, fallback: string): string {
  const last = (name ?? "").normalize("NFC").split(/[\\/]/u).pop() ?? "";
  const cleaned = last
    .replace(UNSAFE, "")
    .replace(RESERVED, "")
    .replace(/\s+/gu, " ")
    .replace(/^[.\s]+/u, "")
    .replace(/[.\s]+$/u, "");
  return cleaned === "" ? fallback : clip(cleaned);
}

/**
 * Wraps a file for encryption: the container, with the name stored already cleaned.
 *
 * @throws PackFormatError when the cleaned name does not fit the header, which clipping prevents.
 */
export function packFile(file: { name: string; bytes: Uint8Array }): Uint8Array {
  const header = new TextEncoder().encode(JSON.stringify({ name: cleanFilename(file.name, "pack") }));
  if (header.length > MAX_HEADER_BYTES) throw new PackFormatError("The file's name does not fit the pack header.");
  const out = new Uint8Array(CONTAINER_FIXED_BYTES + header.length + file.bytes.length);
  out.set(MAGIC, 0);
  out[MAGIC.length] = header.length >> 8;
  out[MAGIC.length + 1] = header.length & 0xff;
  out.set(header, CONTAINER_FIXED_BYTES);
  out.set(file.bytes, CONTAINER_FIXED_BYTES + header.length);
  return out;
}

function startsWithMagic(bytes: Uint8Array): boolean {
  if (bytes.length < MAGIC.length) return false;
  for (let i = 0; i < MAGIC.length; i++) if (bytes[i] !== MAGIC[i]) return false;
  return true;
}

/**
 * Reads a decrypted pack. Bytes that start with the container's magic are read as a container;
 * anything else is the file itself with no name.
 *
 * @returns The file's bytes (a view into `plaintext`) and its stored name, cleaned again on the way out.
 * @throws PackFormatError for a container whose header is cut short, too long, or not `{"name": string}`.
 */
export function unpackFile(plaintext: Uint8Array): { name: string | undefined; bytes: Uint8Array } {
  if (!startsWithMagic(plaintext)) return { name: undefined, bytes: plaintext };
  if (plaintext.length < CONTAINER_FIXED_BYTES) throw new PackFormatError("The pack's container is cut short.");
  const headerLength = ((plaintext[MAGIC.length] ?? 0) << 8) | (plaintext[MAGIC.length + 1] ?? 0);
  if (headerLength < 2 || headerLength > MAX_HEADER_BYTES || CONTAINER_FIXED_BYTES + headerLength > plaintext.length) throw new PackFormatError("The pack's header length is not one this app writes.");
  let header: unknown;
  try {
    header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext.subarray(CONTAINER_FIXED_BYTES, CONTAINER_FIXED_BYTES + headerLength)));
  } catch {
    throw new PackFormatError("The pack's header cannot be read.");
  }
  if (header === null || typeof header !== "object" || Array.isArray(header) || typeof (header as { name?: unknown }).name !== "string") throw new PackFormatError("The pack's header does not name a file.");
  return { name: cleanFilename((header as { name: string }).name, "pack"), bytes: plaintext.subarray(CONTAINER_FIXED_BYTES + headerLength) };
}

/** What the page may do with a decrypted file: show it as text, show it as an image in a sandboxed frame, or only offer it as a download. */
export type PackKind = "text" | "image/png" | "image/jpeg" | "download";

const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const JPEG = [0xff, 0xd8, 0xff];
// "%PDF-": a PDF can open with plain characters, so it is told by its first bytes before the text test.
const PDF = [0x25, 0x50, 0x44, 0x46, 0x2d];
const startsWith = (bytes: Uint8Array, head: readonly number[]): boolean => bytes.length >= head.length && head.every((b, i) => bytes[i] === b);
// Text may hold tabs and line ends; any other control character means it is not something to print.
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;

/**
 * Decides from the bytes alone, never from a name or a declared type, what the page may do with a
 * decrypted file (threat model C20). Text is shown as text. PNG and JPEG are shown as images, and
 * only inside a sandboxed frame. Everything else only downloads: markup of any kind (HTML, SVG,
 * XML, even when it is valid text), PDFs, and bytes that are not clean text.
 */
export function kindOf(bytes: Uint8Array): PackKind {
  if (bytes.length === 0) return "download";
  if (startsWith(bytes, PNG)) return "image/png";
  if (startsWith(bytes, JPEG)) return "image/jpeg";
  if (startsWith(bytes, PDF)) return "download";
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return "download";
  }
  if (CONTROL.test(decoded)) return "download";
  if (decoded.replace(/^﻿/u, "").trimStart().startsWith("<")) return "download";
  return "text";
}
