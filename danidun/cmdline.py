"""Windows command-line parsing without ever involving a shell."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable, Mapping

_ENV_RE = re.compile(r"%([^%\s]+)%")


def expand_env(text: str, env: Mapping[str, str] | None = None) -> str:
    """Expand %VAR% references case-insensitively; unknown variables are left untouched."""
    source = os.environ if env is None else env
    lookup = {k.upper(): v for k, v in source.items()}
    return _ENV_RE.sub(lambda m: lookup.get(m.group(1).upper(), m.group(0)), text or "")


def split_args(cmd: str) -> list[str]:
    """Pure-Python equivalent of CommandLineToArgvW (used for analysis and tests)."""
    args: list[str] = []
    i, n = 0, len(cmd)
    while i < n and cmd[i] in " \t":
        i += 1
    if i >= n:
        return args
    # argv[0] follows simpler rules: quotes delimit, no backslash escaping.
    if cmd[i] == '"':
        end = cmd.find('"', i + 1)
        end = n if end == -1 else end
        args.append(cmd[i + 1:end])
        i = end + 1
    else:
        start = i
        while i < n and cmd[i] not in " \t":
            i += 1
        args.append(cmd[start:i])
    while True:
        while i < n and cmd[i] in " \t":
            i += 1
        if i >= n:
            return args
        buf: list[str] = []
        in_quotes = False
        while i < n:
            ch = cmd[i]
            if ch == "\\":
                count = 0
                while i < n and cmd[i] == "\\":
                    count += 1
                    i += 1
                if i < n and cmd[i] == '"':
                    buf.append("\\" * (count // 2))
                    if count % 2:
                        buf.append('"')
                        i += 1
                else:
                    buf.append("\\" * count)
                continue
            if ch == '"':
                if in_quotes and i + 1 < n and cmd[i + 1] == '"':
                    buf.append('"')
                    i += 2
                    continue
                in_quotes = not in_quotes
                i += 1
                continue
            if ch in " \t" and not in_quotes:
                break
            buf.append(ch)
            i += 1
        args.append("".join(buf))


@dataclass(frozen=True)
class ParsedCommand:
    executable: str
    arguments: str  # raw remainder, passed verbatim to the target executable
    resolved: bool  # executable exists on disk


def parse_command(cmd: str, exists: Callable[[str], bool] = os.path.isfile,
                  env: Mapping[str, str] | None = None) -> ParsedCommand:
    """Split an UninstallString into executable and raw argument string.

    Unquoted paths containing spaces are common in the registry. Like CreateProcess we
    try every whitespace boundary, but we pick the *longest* existing executable so a
    planted ``C:\\Program.exe`` can never hijack ``C:\\Program Files\\...``.
    """
    text = expand_env((cmd or "").strip(), env)
    if not text:
        return ParsedCommand("", "", False)
    if text.startswith('"'):
        end = text.find('"', 1)
        exe, rest = (text[1:], "") if end == -1 else (text[1:end], text[end + 1:])
        exe = exe.strip()
        return ParsedCommand(exe, rest.strip(), bool(exe) and exists(exe))
    boundaries = [m.start() for m in re.finditer(r"[ \t]", text)] + [len(text)]
    best: ParsedCommand | None = None
    for pos in boundaries:
        candidate = text[:pos].rstrip()
        for c in (candidate, candidate + ".exe"):
            if c and exists(c):
                best = ParsedCommand(c, text[pos:].strip(), True)
                break
    if best:
        return best
    first, _, rest = text.partition(" ")
    return ParsedCommand(first, rest.strip(), False)


def quote_arg(arg: str) -> str:
    """Quote a single argument following the MSVCRT rules (inverse of split_args)."""
    if arg and not re.search(r'[\s"]', arg):
        return arg
    out = ['"']
    backslashes = 0
    for ch in arg:
        if ch == "\\":
            backslashes += 1
            continue
        if ch == '"':
            out.append("\\" * (backslashes * 2 + 1) + '"')
        else:
            out.append("\\" * backslashes + ch)
        backslashes = 0
    out.append("\\" * (backslashes * 2) + '"')
    return "".join(out)
