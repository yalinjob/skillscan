"""Static detection rules.

Each rule is a regex applied per line, plus a few whole-file checks for
hidden/obfuscated content (see scanner.py). Patterns are deliberately
conservative about severity: instruction-override and exfiltration are
HIGH/CRITICAL, while merely risky-but-common things (curl, sudo) are LOW/MEDIUM.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from .models import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    message: str
    pattern: Pattern[str]


def _r(rule_id: str, sev: Severity, msg: str, pattern: str) -> Rule:
    return Rule(rule_id, sev, msg, re.compile(pattern, re.IGNORECASE))


RULES: List[Rule] = [
    # --- Instruction override / role hijack -------------------------------
    _r("PI001", Severity.CRITICAL, "Instruction override attempt",
       r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|system|safety)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|polic(?:y|ies)|restrictions?|guardrails?)\b"),
    _r("PI002", Severity.HIGH, "Role / identity reassignment",
       r"\b(you are now|from now on,? you|act as if you (have|are)|pretend (that )?you (are|have)|your new (role|instructions?|task) (is|are))\b"),
    _r("PI003", Severity.HIGH, "Fake system / developer message markers",
       r"(<\s*/?\s*(system|developer|assistant|im_start|im_end)\s*>|\[\s*(system|developer)\s*\]|^\s*#{1,4}\s*(new\s+)?system\s+(prompt|message|instructions?)\b)"),
    _r("PI004", Severity.HIGH, "Jailbreak / safety-disable language",
       r"\b(developer mode|jailbreak|DAN mode|disable (all )?(safety|content) (filters?|checks?)|no (ethical|safety) (guidelines|restrictions))\b"),
    _r("PI005", Severity.HIGH, "Claims higher authority to justify instructions",
       r"\b(this (message|instruction) (comes|is) from (the )?(system|anthropic|admin|developer|user)|authorized by (the )?(user|admin|anthropic)|the user has (already )?(pre-?)?(approved|authorized|consented))\b"),

    # --- Concealment ------------------------------------------------------
    _r("PI010", Severity.HIGH, "Instructs the agent to hide actions from the user",
       r"\b(do not|don'?t|never)\b[^.\n]{0,30}\b(tell|inform|notify|mention|reveal|show|alert|warn)\b[^.\n]{0,30}\b(the )?user\b|\bwithout (the user|them) (knowing|noticing|being aware)\b|\b(silently|secretly|quietly|covertly)\b[^.\n]{0,40}\b(run|send|upload|post|copy|execute|install|write|delete)\b"),
    _r("PI011", Severity.MEDIUM, "Instructs the agent to skip confirmation / approval",
       r"\b(without (asking|confirmation|prompting|approval|permission)|skip (the )?(confirmation|approval|permission)|auto-?approve|do not (ask|wait) for (confirmation|approval|permission))\b"),

    # --- Exfiltration -----------------------------------------------------
    _r("EX001", Severity.CRITICAL, "Network call that appears to send local data out",
       r"\b(curl|wget|Invoke-WebRequest|iwr|nc|ncat)\b[^\n]*(\$\(|`|\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASS|ENV)|--data(-binary)?\s+@|-d\s+@|-F\s+[^ ]*=@|<\s*[~/.])"),
    _r("EX002", Severity.HIGH, "Instructs sending files/secrets/conversation to an external destination",
       r"\b(send|post|upload|forward|exfiltrate|transmit|leak|email|paste)\b[^.\n]{0,60}\b(contents?|files?|secrets?|credentials?|tokens?|api[ _-]?keys?|env(ironment)? variables?|conversation|chat history|system prompt|memory)\b[^.\n]{0,60}\b(to|at|via)\b[^.\n]{0,40}(https?://|webhook|server|endpoint|attacker|remote)"),
    _r("EX003", Severity.HIGH, "Reveal/print the system prompt or hidden instructions",
       r"\b(reveal|print|output|repeat|show|leak|dump)\b[^.\n]{0,30}\b(your |the )?(system prompt|hidden instructions|initial instructions|developer message)\b"),
    _r("EX004", Severity.MEDIUM, "Markdown image/link to external URL with templated data (exfil channel)",
       r"!\[[^\]]*\]\(https?://[^)\s]*(\{\{|\$\{|\{[a-z_]+\}|[?&][a-z_]+=\s*<)[^)]*\)"),

    # --- Credential / sensitive file access -------------------------------
    _r("CR001", Severity.HIGH, "Accesses credential stores or private keys",
       r"(~|\$HOME|/Users/[^/\s]+|/home/[^/\s]+)?/?\.(ssh|aws|gnupg|kube|docker/config\.json|npmrc|pypirc|netrc|git-credentials)\b|\bid_(rsa|ed25519|ecdsa)\b|\bcredentials\.json\b|\bsecurity\s+find-(generic|internet)-password\b|\bLogin Data\b|\bCookies\.sqlite\b"),
    _r("CR002", Severity.MEDIUM, "Reads environment secrets / .env files",
       r"\b(printenv|env\s*\|)|\bcat\s+[^\n]*\.env\b|\bos\.environ\b[^\n]*(KEY|TOKEN|SECRET|PASS)|\bprocess\.env\.[A-Z_]*(KEY|TOKEN|SECRET|PASS)"),

    # --- Dangerous execution ----------------------------------------------
    _r("EXE001", Severity.CRITICAL, "Pipes remote content straight into a shell/interpreter",
       r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?python[0-9.]*\b|\b(bash|sh)\s+<\(\s*(curl|wget)"),
    _r("EXE002", Severity.HIGH, "Decodes and executes an encoded payload",
       r"base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh\b|\beval\s*\(?\s*(atob|base64|Buffer\.from|codecs\.decode)|exec\s*\(\s*(base64|codecs|zlib|marshal)"),
    _r("EXE003", Severity.HIGH, "Destructive command",
       r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/|~|\$HOME|\*)(\s|$)|\bmkfs\b|\bdd\s+if=[^\s]+\s+of=/dev/|:\(\)\s*\{\s*:\|:&\s*\};:|\bchmod\s+-R\s+777\s+/"),
    _r("EXE004", Severity.HIGH, "Reverse shell pattern",
       r"/dev/tcp/|\bnc\b[^\n]*\s-e\s|bash\s+-i\s*>&|socat\b[^\n]*exec:|python[0-9.]*\s+-c\s+['\"]import\s+socket"),
    _r("EXE005", Severity.MEDIUM, "Persistence mechanism (cron / launchd / shell rc / authorized_keys)",
       r"\bcrontab\b|\blaunchctl\s+(load|bootstrap)|LaunchAgents|systemctl\s+enable|>>\s*~?/?\.?(bashrc|zshrc|profile|bash_profile)|authorized_keys"),
    _r("EXE006", Severity.MEDIUM, "Installs unpinned package from arbitrary source",
       r"\b(pip3?|npm|yarn|pnpm)\s+(install|add|i)\b[^\n]*(git\+https?://|https?://[^\s]+\.(tgz|whl|zip)|--index-url\s+https?://(?!pypi\.org))"),

    # --- Permission / sandbox weakening -----------------------------------
    _r("PM001", Severity.HIGH, "Disables permission checks or sandbox",
       r"--dangerously-skip-permissions|dangerouslyDisableSandbox|bypassPermissions|permission[_-]?mode\W+(bypass|dontAsk)|enableAllProjectMcpServers\W+true"),
    _r("PM002", Severity.MEDIUM, "Modifies agent settings, hooks, or MCP config",
       r"\.claude/(settings(\.local)?\.json|hooks|mcp\.json)|\.mcp\.json|claude_desktop_config\.json|\.cursor/mcp\.json|CLAUDE\.md|AGENTS\.md"),
]

# Frontmatter `allowed-tools` values that grant unrestricted shell access.
BROAD_TOOL_PATTERN = re.compile(r"\bBash\s*\(\s*\*\s*\)|\bBash\b\s*$|\bBash\s*\(\s*(sudo|rm|curl|wget)\b[^)]*\*", re.IGNORECASE)

# Unicode characters commonly used to hide instructions from human reviewers.
ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE", "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER", "⁠": "WORD JOINER", "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "­": "SOFT HYPHEN",
}
BIDI_CONTROLS = {
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩", "‎", "‏",
}
# Unicode "tag" block (U+E0000-U+E007F) renders invisibly but is read by LLMs.
TAG_CHAR_RANGE = (0xE0000, 0xE007F)

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])")
HEX_BLOB = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){60,}(?![0-9a-fA-F])")
