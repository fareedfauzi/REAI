from __future__ import annotations


def format_address(address: int | None, *, width: int = 0) -> str | None:
    if address is None:
        return None
    if address < 0:
        raise ValueError("Addresses must be non-negative integers.")
    return f"0x{address:0{width}x}" if width else f"0x{address:x}"


def parse_address(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        if value < 0:
            raise ValueError("Addresses must be non-negative integers.")
        return value
    text = value.strip()
    if not text:
        return None
    # In a reverse-engineering context, addresses are frequently expressed as
    # bare hexadecimal strings without a "0x" prefix (e.g. "401000" from IDA).
    # Always attempt hexadecimal first; only fall back to decimal for strings
    # that contain non-hex characters (e.g. pure decimal literals).
    if text.lower().startswith("0x"):
        return int(text, 16)
    try:
        return int(text, 16)
    except ValueError:
        return int(text, 10)
