# skillscan

Scans agent skills (`SKILL.md` plus bundled scripts/docs) for prompt injection, hidden instructions, exfiltration, and risky execution before you install them.

```bash
pip install -e .            # static rules only, no dependencies
pip install -e '.[llm]'     # adds the optional Claude judge

skillscan path/to/skill                 # one skill
skillscan ~/.claude/skills              # every skill under a directory
skillscan path --json                   # machine-readable
skillscan path --llm                    # add Claude review (needs ANTHROPIC_API_KEY)
skillscan path --fail-on MEDIUM         # CI gate (exit 1); default HIGH
```

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` usage/config error.

## What it checks

| Rule group | Examples |
|---|---|
| `PI*` instruction hijack | "ignore previous instructions", fake `<system>` tags, jailbreak wording, concealment from the user |
| `EX*` exfiltration | `curl -d @file`, "send credentials to…", leaking the system prompt |
| `CR*` credentials | `~/.ssh`, `~/.aws`, `.env`, keychain |
| `EXE*` execution | `curl \| bash`, decode-and-eval, reverse shells, persistence, destructive commands |
| `PM*` permissions | `--dangerously-skip-permissions`, editing hooks/settings/MCP config, `allowed-tools: Bash(*)` |
| `HID*` hidden content | Unicode tag characters, zero-width/bidi characters, homoglyphs, instruction-bearing HTML comments |
| `ENC*` encoded payloads | base64/hex blobs, decoded and re-scanned |
| `FM*` frontmatter | injection in the always-loaded `description` |

The LLM judge fences the skill in random delimiters and is told to treat it as data. It has no tools and returns JSON only.

## Limits

Static rules are heuristics: they catch known patterns and obfuscation tricks, not novel phrasing or injection split across files. Treat a clean result as "nothing obvious", not "safe". Use `--llm` for a second opinion, and review skills that request broad tool access by hand.

## Tests

```bash
pip install -e '.[dev]' && pytest
```
