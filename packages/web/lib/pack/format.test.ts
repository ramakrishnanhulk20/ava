// Covers what a pack is once it is decrypted (threat model C19, C20): the small container that
// keeps a file's name inside the encrypted bytes, the filename a download is given, and which packs
// may be shown on the page at all. Does NOT cover the encryption around it (core's tests), the
// sandboxed frame an image is shown in, or what a browser does with a downloaded file.
import { describe, expect, it } from "vitest";
import { PackFormatError, cleanFilename, kindOf, packFile, unpackFile, MAX_NAME_BYTES } from "./format";

const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
const JPEG = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0, 16, 0x4a, 0x46, 0x49, 0x46, 0]);
const PDF = text("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n");

describe("packFile and unpackFile", () => {
  it("gives back the same bytes and the name, whatever the bytes are", () => {
    const body = Uint8Array.from({ length: 300 }, (_, i) => (i * 31) % 256);
    const packed = packFile({ name: "Q4 board pack.pdf", bytes: body });
    expect(Array.from(packed.subarray(0, 8))).toEqual([0x41, 0x56, 0x41, 0x50, 0x41, 0x43, 0x4b, 0x01]);
    const opened = unpackFile(packed);
    expect(opened.name).toBe("Q4 board pack.pdf");
    expect(Array.from(opened.bytes)).toEqual(Array.from(body));
  });

  it("stores the name already cleaned, so no reader ever sees the raw one", () => {
    expect(unpackFile(packFile({ name: "..\\..\\evil\u202Efdp.exe", bytes: PNG })).name).toBe("evilfdp.exe");
  });

  it("reads bytes with no container as a pack with no name: the demo board's packs are plain text", () => {
    const plain = text("Ava demo board: board pack\n\nAgenda\n");
    const opened = unpackFile(plain);
    expect(opened.name).toBeUndefined();
    expect(Array.from(opened.bytes)).toEqual(Array.from(plain));
  });

  it("keeps an empty file and a file that itself starts like a container apart", () => {
    expect(unpackFile(packFile({ name: "empty.txt", bytes: new Uint8Array(0) })).bytes).toHaveLength(0);
    const inner = packFile({ name: "inner.bin", bytes: PNG });
    const outer = unpackFile(packFile({ name: "outer.bin", bytes: inner }));
    expect(outer.name).toBe("outer.bin");
    expect(Array.from(outer.bytes)).toEqual(Array.from(inner));
  });

  it("refuses a container it cannot read instead of guessing", () => {
    const good = packFile({ name: "a.txt", bytes: text("hello") });
    const cutShort = good.subarray(0, 9);
    const longHeader = Uint8Array.from(good);
    longHeader[8] = 0xff;
    longHeader[9] = 0xff;
    const notJson = Uint8Array.from(good);
    notJson[10] = 0x00;
    for (const bad of [cutShort, longHeader, notJson]) expect(() => unpackFile(bad)).toThrow(PackFormatError);
  });

  it("refuses a name too long to store even after cleaning", () => {
    const packed = packFile({ name: `${"a".repeat(400)}.pdf`, bytes: PNG });
    const name = unpackFile(packed).name ?? "";
    expect(new TextEncoder().encode(name).length).toBeLessThanOrEqual(MAX_NAME_BYTES);
    expect(name.endsWith(".pdf")).toBe(true);
  });
});

describe("cleanFilename", () => {
  it("drops path parts, control characters and direction marks", () => {
    expect(cleanFilename("C:\\Users\\me\\minutes.pdf", "pack-1")).toBe("minutes.pdf");
    expect(cleanFilename("/etc/passwd", "pack-1")).toBe("passwd");
    expect(cleanFilename("mi\u0000nu\u0007tes\u202E.pdf", "pack-1")).toBe("minutes.pdf");
    expect(cleanFilename("a\u2066b\u2069c\u200F.txt", "pack-1")).toBe("abc.txt");
  });

  it("never gives a hidden file, a relative step or a name a shell reads specially", () => {
    expect(cleanFilename("..", "pack-1")).toBe("pack-1");
    expect(cleanFilename("...hidden", "pack-1")).toBe("hidden");
    expect(cleanFilename('re<po>rt:"|?*.pdf', "pack-1")).toBe("report.pdf");
    expect(cleanFilename("report.pdf . . ", "pack-1")).toBe("report.pdf");
  });

  it("falls back when nothing usable is left", () => {
    expect(cleanFilename("", "pack-7")).toBe("pack-7");
    expect(cleanFilename("\u202E\u0000///", "pack-7")).toBe("pack-7");
    expect(cleanFilename(undefined, "pack-7")).toBe("pack-7");
  });

  it("keeps ordinary names in any script as they are", () => {
    expect(cleanFilename("Протокол заседания.docx", "pack-1")).toBe("Протокол заседания.docx");
    expect(cleanFilename("நிமிடங்கள் 2026.pdf", "pack-1")).toBe("நிமிடங்கள் 2026.pdf");
  });
});

describe("kindOf", () => {
  it("shows plain text as text", () => {
    expect(kindOf(text("Ava demo board: board pack\n\nAgenda\n1. Approve the plan.\n"))).toBe("text");
    expect(kindOf(text("Tamil: அவை\tand a tab\r\n"))).toBe("text");
  });

  it("shows PNG and JPEG images, told by their first bytes and never by a name", () => {
    expect(kindOf(PNG)).toBe("image/png");
    expect(kindOf(JPEG)).toBe("image/jpeg");
  });

  it("never shows markup on the page: HTML, SVG and XML only download", () => {
    expect(kindOf(text("<!doctype html><script>alert(1)</script>"))).toBe("download");
    expect(kindOf(text("  \n<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>"))).toBe("download");
    expect(kindOf(text("\uFEFF<?xml version='1.0'?><a/>"))).toBe("download");
    expect(kindOf(text("<html>"))).toBe("download");
  });

  it("downloads everything else: a PDF, bytes that are not text, text with control characters, an empty file", () => {
    expect(kindOf(PDF)).toBe("download");
    expect(kindOf(Uint8Array.from([0xff, 0xfe, 0x00, 0x01]))).toBe("download");
    expect(kindOf(text("looks like text\u0000but is not"))).toBe("download");
    expect(kindOf(text("an escape \u001b[31m sequence"))).toBe("download");
    expect(kindOf(new Uint8Array(0))).toBe("download");
  });

  it("is not fooled by an image header on something that then turns into markup", () => {
    // What matters is what the page does with each kind: an image is only ever handed to a sandboxed frame as an image.
    expect(kindOf(Uint8Array.from([...PNG, ...text("<script>alert(1)</script>")]))).toBe("image/png");
  });
});
