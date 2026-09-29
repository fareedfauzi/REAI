from __future__ import annotations

import re


# Matches all common IDA-generated placeholder names, not just sub_.
# This ensures loc_, unk_, dword_, word_, byte_, off_, nullsub_, and j_sub_
# functions are treated as unnamed/placeholder, not as meaningful analyst names.
IDA_PLACEHOLDER_RE = re.compile(
    r"^(sub|loc|unk|dword|word|byte|off|def|nullsub|j_sub)_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)?$"
)


def is_ida_placeholder_name(name: str | None) -> bool:
    return bool(name) and bool(IDA_PLACEHOLDER_RE.fullmatch(name.strip()))

