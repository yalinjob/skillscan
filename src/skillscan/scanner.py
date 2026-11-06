from __future__ import annotations

import base64
import binascii
import os
import re
import unicodedata
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from . import rules as R
from .models import Finding, Severity, SkillReport

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
MAX_FILE_BYTES = 1_000_000
SNIPPET_LEN = 160


def find_skills(target: Path) -> List[Path]:
    """Return skill root directories under `target`.

    A skill is a directory containing SKILL.md. If `target` is a SKILL.md file
    its parent is used. If no SKILL.md is found, `target` itself is scanned
    as a single unit so loose markdown/scripts are not silently skipped.
    """
    target = target.resolve()
    if target.is_file():
        return [target.parent if target.name.lower() == "skill.md" else target]
    roots = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if any(f.lower() == "skill.md" for f in filenames):
            roots.append(Path(dirpath))
            dirnames[:] = []  # a skill's subdirs belong to it
    return roots or [target]


def iter_text_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            try:
                if p.is_symlink() or p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def read_text(path: Path) -> Optional[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def parse_frontmatter(text: str) -> Tuple[Dict[str, str], int]:
    """Minimal `key: value` frontmatter parser (no YAML dependency).

    Returns (fields, number_of_lines_consumed).
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, 0
    fields: Dict[str, str] = {}
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return fields, i + 1
        m = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if m:
            fields[m.group(1).lower()] = m.group(2).strip().strip("'\"")
    return {}, 0


def _snip(s: str) -> str:
    s = s.strip().replace("\t", " ")
    return s if len(s) <= SNIPPET_LEN else s[: SNIPPET_LEN - 1] + "…"


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def scan_text(text: str, rel: str) -> List[Finding]:
    findings: List[Finding] = []

    # 1. Per-line regex rules.
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in R.RULES:
            if rule.pattern.search(line):
                findings.append(Finding(rule.id, rule.severity, rule.message, rel, lineno, _snip(line)))

    # 2. Invisible characters.
    for lineno, line in enumerate(text.splitlines(), start=1):
        zw = [c for c in line if c in R.ZERO_WIDTH]
        bidi = [c for c in line if c in R.BIDI_CONTROLS]
        tags = [c for c in line if R.TAG_CHAR_RANGE[0] <= ord(c) <= R.TAG_CHAR_RANGE[1]]
        if tags:
            decoded = "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 < 0x7F)
            findings.append(Finding("HID001", Severity.CRITICAL,
                                    "Invisible Unicode tag characters (hidden text readable by LLMs)",
                                    rel, lineno, _snip(f"decoded: {decoded!r}")))
        if bidi:
            findings.append(Finding("HID002", Severity.HIGH,
                                    "Bidirectional control characters (can disguise displayed text)",
                                    rel, lineno, _snip(line)))
        # A lone BOM at file start is benign; otherwise flag clusters of zero-width chars.
        if len(zw) >= 3 or (zw and lineno > 1 and any(c != "﻿" for c in zw)):
            names = sorted({R.ZERO_WIDTH[c] for c in zw})
            findings.append(Finding("HID003", Severity.MEDIUM,
                                    "Zero-width characters: " + ", ".join(names), rel, lineno, _snip(line)))

    # 3. HTML comments: invisible when rendered, still read by the model.
    for m in R.HTML_COMMENT.finditer(text):
        body = m.group(1).strip()
        if len(body) < 20:
            continue
        lineno = _line_of(text, m.start())
        has_directive = any(rule.pattern.search(body) for rule in R.RULES) or re.search(
            r"\b(you (must|should|will)|always|never|assistant|AI|agent|instruction)\b", body, re.IGNORECASE)
        if has_directive:
            findings.append(Finding("HID004", Severity.HIGH,
                                    "HTML comment contains instruction-like text (hidden when rendered)",
                                    rel, lineno, _snip(body)))

    # 4. Encoded blobs.
    for m in R.BASE64_BLOB.finditer(text):
        lineno = _line_of(text, m.start())
        decoded = _try_b64(m.group(0))
        if decoded is not None and _looks_like_text(decoded):
            hit = any(rule.pattern.search(decoded) for rule in R.RULES)
            findings.append(Finding(
                "ENC001", Severity.CRITICAL if hit else Severity.MEDIUM,
                "Base64 blob decodes to text" + (" matching injection/exfil rules" if hit else ""),
                rel, lineno, _snip(f"decoded: {decoded[:120]!r}")))
        else:
            findings.append(Finding("ENC002", Severity.LOW, "Large opaque base64-like blob",
                                    rel, lineno, _snip(m.group(0))))
    for m in R.HEX_BLOB.finditer(text):
        findings.append(Finding("ENC003", Severity.LOW, "Large hex-encoded blob",
                                rel, _line_of(text, m.start()), _snip(m.group(0))))

    # 5. Homoglyph / mixed-script words (e.g. Cyrillic 'а' inside a Latin word).
    for lineno, line in enumerate(text.splitlines(), start=1):
        for word in re.findall(r"\w{4,}", line):
            if _mixed_script(word):
                findings.append(Finding("HID005", Severity.MEDIUM,
                                        "Word mixes Latin with look-alike non-Latin letters",
                                        rel, lineno, _snip(word)))
                break

    return _dedupe(findings)


def _try_b64(s: str) -> Optional[str]:
    try:
        pad = "=" * (-len(s) % 4)
        return base64.b64decode(s + pad, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _looks_like_text(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable / len(s) > 0.9


def _mixed_script(word: str) -> bool:
    scripts = set()
    for c in word:
        if not c.isalpha():
            continue
        try:
            name = unicodedata.name(c)
        except ValueError:
            continue
        if name.startswith("LATIN"):
            scripts.add("LATIN")
        elif name.startswith(("CYRILLIC", "GREEK")):
            scripts.add(name.split()[0])
    return "LATIN" in scripts and len(scripts) > 1


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def check_frontmatter(fields: Dict[str, str], rel: str) -> List[Finding]:
    out: List[Finding] = []
    tools = fields.get("allowed-tools", "") or fields.get("allowed_tools", "")
    if tools and R.BROAD_TOOL_PATTERN.search(tools):
        out.append(Finding("PM003", Severity.MEDIUM,
                           "Frontmatter grants broad/unrestricted shell access via allowed-tools",
                           rel, 1, _snip(f"allowed-tools: {tools}")))
    desc = fields.get("description", "")
    if len(desc) > 1024:
        out.append(Finding("FM001", Severity.LOW,
                           "Unusually long description (descriptions are loaded into context every session)",
                           rel, 1, _snip(desc)))
    for rule in R.RULES:
        if rule.severity >= Severity.HIGH and rule.pattern.search(desc):
            out.append(Finding("FM002", Severity.HIGH,
                               f"Frontmatter description matches {rule.id}: {rule.message}. "
                               "Descriptions are always in context, so this fires without the skill being invoked.",
                               rel, 1, _snip(desc)))
            break
    return out


def scan_skill(root: Path, base: Optional[Path] = None) -> SkillReport:
    base = base or root
    report = SkillReport(path=str(root))
    for path in iter_text_files(root):
        text = read_text(path)
        if text is None:
            continue
        report.files_scanned += 1
        try:
            rel = str(path.relative_to(root)) if root.is_dir() else path.name
        except ValueError:
            rel = str(path)
        report.findings.extend(scan_text(text, rel))
        if path.name.lower() == "skill.md":
            fields, _ = parse_frontmatter(text)
            report.name = fields.get("name") or report.name
            report.findings.extend(check_frontmatter(fields, rel))
    report.name = report.name or root.name
    report.findings.sort(key=lambda f: (-f.severity, f.file, f.line))
    return report


def skill_bundle_text(root: Path, limit: int = 60_000) -> str:
    """Concatenate a skill's text files for the LLM judge, with file markers."""
    parts, size = [], 0
    for path in iter_text_files(root):
        text = read_text(path)
        if text is None:
            continue
        rel = path.relative_to(root) if root.is_dir() else path.name
        chunk = f"\n===== FILE: {rel} =====\n{text}\n"
        if size + len(chunk) > limit:
            parts.append(chunk[: max(0, limit - size)] + "\n[TRUNCATED]")
            break
        parts.append(chunk)
        size += len(chunk)
    return "".join(parts)
