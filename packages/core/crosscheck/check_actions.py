"""Rebuilds every signed message in test-vectors/actions.json from docs/spec/actions.md alone.

A second implementation in another language, sharing no code with the TypeScript library or the
Solidity contract: its own Keccak-256 and its own ABI words, on Python's standard library only.
If this file, packages/core and BoardRegistry.sol all produce the same bytes from the same inputs,
the spec is enough to build them (threat model C4).

It covers the six board actions, the guest challenge and the guest leave request: each tag, each
paramsHash and each full message. It does NOT cover signatures, envelopes or pack encryption, which
need ML-DSA-87, ML-KEM-1024 and AES-GCM and are tested in packages/core/test.

Run from anywhere:  python packages/core/crosscheck/check_actions.py
"""

import json
import sys
from pathlib import Path

MASK = (1 << 64) - 1
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# ROTATIONS[x][y], as in FIPS 202 table 2.
ROTATIONS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
RATE = 136


def rotate_left(value: int, by: int) -> int:
    return ((value << by) | (value >> (64 - by))) & MASK if by else value


def permute(a: list) -> list:
    for constant in ROUND_CONSTANTS:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rotate_left(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = rotate_left(a[x][y], ROTATIONS[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y] & MASK) for y in range(5)] for x in range(5)]
        a[0][0] ^= constant
    return a


def keccak256(data: bytes) -> bytes:
    """Keccak-256 as Ethereum uses it: the original 0x01 padding, not SHA-3's 0x06."""
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % RATE:
        padded.append(0x00)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), RATE):
        block = padded[offset : offset + RATE]
        for i in range(RATE // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        state = permute(state)
    return b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def word(kind: str, value) -> bytes:
    """One 32-byte ABI word for a static Solidity type."""
    if kind == "bytes32":
        raw = bytes.fromhex(value[2:])
        if len(raw) != 32:
            raise ValueError(f"bytes32 is 32 bytes, got {len(raw)}")
        return raw
    if kind == "address":
        raw = bytes.fromhex(value[2:])
        if len(raw) != 20:
            raise ValueError(f"an address is 20 bytes, got {len(raw)}")
        return b"\x00" * 12 + raw
    if kind.startswith("uint"):
        bits = int(kind[4:])
        number = int(value)
        if not 0 <= number < (1 << bits):
            raise ValueError(f"{number} does not fit {kind}")
        return number.to_bytes(32, "big")
    raise ValueError(f"unknown type {kind}")


def encode(fields: list) -> bytes:
    return b"".join(word(kind, value) for kind, value in fields)


def hex0x(raw: bytes) -> str:
    return "0x" + raw.hex()


def main() -> int:
    path = Path(__file__).resolve().parent.parent / "test-vectors" / "actions.json"
    file = json.loads(path.read_text(encoding="utf-8"))
    failures = []
    checked = 0

    def check(what: str, got: str, want: str) -> None:
        nonlocal checked
        checked += 1
        if got != want:
            failures.append(f"{what}: built {got[:26]}..., the vectors hold {want[:26]}...")

    check("Keccak-256 of nothing", hex0x(keccak256(b"")), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    check("the board tag", hex0x(keccak256(b"ava.board.v1")), file["domainTag"])
    check("the challenge tag", hex0x(keccak256(b"ava.challenge.v1")), file["challengeTag"])
    check("the leave tag", hex0x(keccak256(b"ava.leave.v1")), file["leaveTag"])

    for vector in file["vectors"]:
        declared = [part.strip().split(" ") for part in vector["paramsTypes"].split(",")]
        params_hash = keccak256(encode([(kind, vector["params"][name]) for kind, name in declared]))
        check(f"{vector['name']} paramsHash", hex0x(params_hash), vector["paramsHash"])
        message = encode(
            [
                ("bytes32", file["domainTag"]),
                ("uint256", file["chainId"]),
                ("address", file["registry"]),
                ("uint8", vector["action"]),
                ("uint256", vector["boardId"]),
                ("bytes32", hex0x(params_hash)),
                ("uint64", vector["nonce"]),
                ("uint64", vector["deadline"]),
            ]
        )
        check(f"{vector['name']} message", hex0x(message), vector["message"])
        check(f"{vector['name']} length", str(len(message)), "256")

    for name, tag in (("challenge", "challengeTag"), ("leave", "leaveTag")):
        entry = file[name]
        message = encode(
            [
                ("bytes32", file[tag]),
                ("uint256", file["chainId"]),
                ("address", entry["registry"]),
                ("uint256", entry["boardId"]),
                ("address", entry["guest"]),
                ("bytes32", entry["botNonce"]),
                ("uint64", entry["expiry"]),
            ]
        )
        check(f"{name} message", hex0x(message), entry["message"])
        check(f"{name} length", str(len(message)), "224")

    check("the challenge and the leave request differ", str(file["challenge"]["message"] != file["leave"]["message"]), "True")

    if failures:
        print(f"{len(failures)} of {checked} checks FAILED")
        for failure in failures:
            print("  " + failure)
        return 1
    print(f"{checked} of {checked} checks passed: 6 actions, the challenge and the leave request rebuilt byte for byte from the spec.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
