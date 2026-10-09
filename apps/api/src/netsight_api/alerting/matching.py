"""Linear-time text matching for the ``matches`` operator.

``alert-rule.schema.json`` requires the pattern to be evaluated with a linear-time matcher,
never a backtracking engine: a rule author (or an attacker who got a rule written) must not
be able to stall the evaluator with a catastrophic pattern. The pattern language is
therefore a glob, not a regular expression: ``*`` matches any run (including none), ``?``
matches one character, everything else is literal and case-sensitive.

The matcher is a bit-parallel simulation of the pattern's NFA (Shift-And with wildcards):
the set of live pattern positions is one Python integer, so each text character costs a
handful of big-integer operations regardless of the pattern, i.e. O(len(text)) steps for the
pattern sizes the contract allows (256 characters). Text longer than ``MAX_MATCH_TEXT_LENGTH``
never matches rather than burning CPU.
"""

from __future__ import annotations

from typing import Final

MAX_MATCH_TEXT_LENGTH: Final = 4096


def _collapse_stars(pattern: str) -> str:
    out: list[str] = []
    for char in pattern:
        if char == "*" and out and out[-1] == "*":
            continue
        out.append(char)
    return "".join(out)


def glob_matches(pattern: str, text: str) -> bool:
    """True when the whole of ``text`` matches ``pattern`` (``*`` and ``?`` wildcards)."""
    if len(text) > MAX_MATCH_TEXT_LENGTH:
        return False
    tokens = _collapse_stars(pattern)
    final_bit = 1 << len(tokens)
    star_bits = 0
    any_bits = 0  # positions whose token matches every character ('?')
    literal_bits: dict[str, int] = {}
    for position, token in enumerate(tokens):
        bit = 1 << position
        if token == "*":
            star_bits |= bit
        elif token == "?":
            any_bits |= bit
        else:
            literal_bits[token] = literal_bits.get(token, 0) | bit

    # State bit i: the first i tokens are matched. A star can match nothing, so a state on a
    # star also puts the next state in play (stars are collapsed, so one step is enough).
    state = 1 | ((1 & star_bits) << 1)
    for char in text:
        step = state & (any_bits | literal_bits.get(char, 0))
        state = (step << 1) | (state & star_bits)
        state |= (state & star_bits) << 1
        if not state:
            return False
    return bool(state & final_bit)
