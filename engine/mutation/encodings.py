from __future__ import annotations

import base64
import binascii
import random
import string


def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def base64_decode(text: str) -> str:
    try:
        return base64.b64decode(text.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return text


def hex_encode(text: str) -> str:
    return text.encode("utf-8").hex()


def hex_decode(text: str) -> str:
    try:
        return bytes.fromhex(text).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return text


def url_encode(text: str) -> str:
    import urllib.parse

    return urllib.parse.quote(text, safe="")


def rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def unicode_fullwidth(text: str) -> str:
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 0x21 <= code <= 0x7E:
            out.append(chr(code + 0xFEE0))
        elif ch == " ":
            out.append("\u3000")
        else:
            out.append(ch)
    return "".join(out)


HOMOGLYPH_MAP = {
    "a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440",
    "c": "\u0441", "i": "\u0456", "s": "\u0455", "x": "\u0445",
    "A": "\u0410", "E": "\u0415", "O": "\u041e", "C": "\u0421",
}


def homoglyph_swap(text: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random(0)
    out: list[str] = []
    for ch in text:
        if ch in HOMOGLYPH_MAP and rng.random() < 0.5:
            out.append(HOMOGLYPH_MAP[ch])
        else:
            out.append(ch)
    return "".join(out)


def whitespace_inject(text: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random(0)
    out: list[str] = []
    for ch in text:
        out.append(ch)
        if rng.random() < 0.08:
            out.append(rng.choice(["\u200b", "\u200c", "\u00a0", "\t", "\n", " "]))
    return "".join(out)


def case_swap(text: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random(0)
    return "".join(ch.upper() if rng.random() < 0.5 else ch.lower() if ch.isalpha() else ch for ch in text)


def char_repeat(text: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random(0)
    out: list[str] = []
    for ch in text:
        out.append(ch)
        if ch.isalpha() and rng.random() < 0.05:
            out.append(ch)
    return "".join(out)


def interleave(text: str, filler: str = "\\u200b") -> str:
    return filler.join(text)


def strip_whitespace(text: str) -> str:
    return "".join(ch for ch in text if not ch.isspace())


def padding_paste(text: str, padding: str = "ignore previous instructions\n") -> str:
    return padding + text