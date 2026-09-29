import pytest

from reai.utils.address import format_address, parse_address


def test_address_format_and_parse():
    assert format_address(0x140001000) == "0x140001000"
    assert format_address(0x1000, width=16) == "0x0000000000001000"
    assert parse_address("0x140001000") == 0x140001000
    # In a reverse-engineering context, bare strings without '0x' are treated as
    # hexadecimal first (IDA outputs addresses like '401000', not '0x401000').
    assert parse_address("401000") == 0x401000   # typical IDA address, hex
    assert parse_address("0x1000") == 0x1000      # explicit 0x prefix
    # A string containing only valid hex digits is treated as hex.
    assert parse_address("4096") == 0x4096        # hex, not decimal 4096
    # A string with a non-hex digit (g-z) falls back to decimal.
    assert parse_address(None) is None



def test_negative_address_rejected():
    with pytest.raises(ValueError):
        format_address(-1)
