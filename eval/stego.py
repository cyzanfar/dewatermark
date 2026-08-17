"""Unicode-steganography embedders: covert payloads hidden in cover text.

Five families, mirroring what the remover claims to strip:
  - zero_width:          binary encoding, 0 -> U+200B, 1 -> U+200C
  - variation_selector:  byte < 16 -> U+FE00+b, else U+E0100+(b-16)
  - tags_block:          ASCII b (< 0x80) -> U+E0000+b
  - homoglyph:           payload bits toggle Latin -> Cyrillic lookalikes
  - exotic_space:        payload bits toggle U+0020 -> U+202F

Each embed_X(cover_text, payload: bytes) returns watermarked text.
decode_X extracts the payload again (used by the local self-test).
strip_covert() deterministically removes everything we embed (self-test only).
"""

from __future__ import annotations

ZWSP = "\u200b"  # ZERO WIDTH SPACE
ZWNJ = "\u200c"  # ZERO WIDTH NON-JOINER
EXOTIC_SPACE = "\u202f"  # NARROW NO-BREAK SPACE

# Latin -> Cyrillic lookalikes
HOMOGLYPHS = {
    "a": "\u0430",
    "e": "\u0435",
    "i": "\u0456",
    "o": "\u043e",
    "p": "\u0440",
    "c": "\u0441",
    "x": "\u0445",
    "y": "\u0443",
    "A": "\u0410",
    "B": "\u0412",
    "C": "\u0421",
    "E": "\u0415",
    "H": "\u041d",
    "K": "\u041a",
    "M": "\u041c",
    "O": "\u041e",
    "P": "\u0420",
    "T": "\u0422",
}
HOMOGLYPHS_INV = {v: k for k, v in HOMOGLYPHS.items()}

FAMILIES = ["zero_width", "variation_selector", "tags_block", "homoglyph", "exotic_space"]


def _bits(payload: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1)]


def _distribute(cover: str, hidden: str) -> str:
    """Spread hidden chars evenly through the cover text."""
    if not cover:
        return hidden
    step = max(1, len(cover) // (len(hidden) + 1))
    out, hi = [], 0
    for i, ch in enumerate(cover):
        out.append(ch)
        if hi < len(hidden) and (i + 1) % step == 0:
            out.append(hidden[hi])
            hi += 1
    out.append(hidden[hi:])
    return "".join(out)


def embed_zero_width(cover: str, payload: bytes) -> str:
    hidden = "".join(ZWSP if b == 0 else ZWNJ for b in _bits(payload))
    return _distribute(cover, hidden)


def decode_zero_width(text: str) -> bytes:
    bits = [0 if ch == ZWSP else 1 for ch in text if ch in (ZWSP, ZWNJ)]
    return bytes(int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits) - 7, 8))


def embed_variation_selector(cover: str, payload: bytes) -> str:
    hidden = "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16) for b in payload)
    return _distribute(cover, hidden)


def decode_variation_selector(text: str) -> bytes:
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            out.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            out.append(cp - 0xE0100 + 16)
    return bytes(out)


def embed_tags_block(cover: str, payload: bytes) -> str:
    if any(b >= 0x80 for b in payload):
        raise ValueError("tags_block family carries ASCII payloads only")
    hidden = "".join(chr(0xE0000 + b) for b in payload)
    return _distribute(cover, hidden)


def decode_tags_block(text: str) -> bytes:
    return bytes(ord(ch) - 0xE0000 for ch in text if 0xE0000 <= ord(ch) <= 0xE007F)


def embed_homoglyph(cover: str, payload: bytes) -> str:
    bits = _bits(payload)
    bi, out = 0, []
    for ch in cover:
        if ch in HOMOGLYPHS:
            if bits[bi % len(bits)]:
                ch = HOMOGLYPHS[ch]
            bi += 1
        out.append(ch)
    return "".join(out)


def embed_exotic_space(cover: str, payload: bytes) -> str:
    bits = _bits(payload)
    bi, out = 0, []
    for ch in cover:
        if ch == " ":
            if bits[bi % len(bits)]:
                ch = EXOTIC_SPACE
            bi += 1
        out.append(ch)
    return "".join(out)


EMBEDDERS = {
    "zero_width": embed_zero_width,
    "variation_selector": embed_variation_selector,
    "tags_block": embed_tags_block,
    "homoglyph": embed_homoglyph,
    "exotic_space": embed_exotic_space,
}


def strip_covert(text: str) -> str:
    """Deterministic local stripper (self-test reference for dewatermark.unicode)."""
    out = []
    for ch in text:
        cp = ord(ch)
        if (
            cp in (0x200B, 0x200C, 0x200D)
            or 0xFE00 <= cp <= 0xFE0F
            or 0xE0100 <= cp <= 0xE01EF
            or 0xE0000 <= cp <= 0xE007F
        ):
            continue
        if cp == 0x202F:
            out.append(" ")
            continue
        out.append(HOMOGLYPHS_INV.get(ch, ch))
    return "".join(out)


def _self_test() -> None:
    cover = (
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs. "
        "How vexingly quick daft zebras jump!"
    )
    payload = b"zeroday"

    for family in FAMILIES:
        watermarked = EMBEDDERS[family](cover, payload)
        assert watermarked != cover
        assert strip_covert(watermarked) == cover, family
        print(
            f"[{family}] embed+strip roundtrip OK "
            f"(len {len(cover)} -> {len(watermarked)} -> {len(strip_covert(watermarked))})"
        )

    assert decode_zero_width(embed_zero_width(cover, payload)) == payload
    assert decode_variation_selector(embed_variation_selector(cover, payload)) == payload
    assert decode_tags_block(embed_tags_block(cover, payload)) == payload
    print("[decoders] zero_width / variation_selector / tags_block payload roundtrip OK")
    print("stego self-test OK")


if __name__ == "__main__":
    _self_test()
