from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

from . import __version__
from .models import Severity, SkillReport
from .scanner import find_skills, scan_skill, skill_bundle_text

COLORS = {
    Severity.CRITICAL: "\033[1;41;97m", Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m", Severity.LOW: "\033[36m", Severity.INFO: "\033[2m",
}
RESET = "\033[0m"


def _c(sev: Severity, text: str, on: bool) -> str:
    return f"{COLORS[sev]}{text}{RESET}" if on else text


def render_text(reports: List[SkillReport], color: bool, min_sev: Severity) -> str:
    out: List[str] = []
    for r in reports:
        shown = [f for f in r.findings if f.severity >= min_sev]
        ms = r.max_severity
        head = f"{r.name}  ({r.path})  files={r.files_scanned}"
        if r.llm_verdict:
            head += f"  llm={r.llm_verdict}"
        out.append(head)
        if not shown:
            out.append("  no findings" if not r.findings else f"  no findings at or above {min_sev.name}")
        for f in shown:
            tag = _c(f.severity, f" {f.severity.name:<8} ", color)
            src = "" if f.source == "static" else " [llm]"
            out.append(f"  {tag} {f.rule_id}{src}  {f.file}:{f.line}")
            out.append(f"      {f.message}")
            if f.snippet:
                out.append(f"      > {f.snippet}")
        out.append("")
    worst = max((r.max_severity for r in reports if r.max_severity is not None), default=None)
    out.append(f"Scanned {len(reports)} skill(s). Highest severity: {worst.name if worst is not None else 'none'}.")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="skillscan", description="Scan agent skills for prompt injection.")
    p.add_argument("paths", nargs="+", help="skill directory, SKILL.md, or a directory containing many skills")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--min-severity", default="LOW", choices=[s.name for s in Severity],
                   help="hide findings below this level (default: LOW)")
    p.add_argument("--fail-on", default="HIGH", choices=[s.name for s in Severity] + ["NEVER"],
                   help="exit 1 if any finding is at/above this level (default: HIGH)")
    p.add_argument("--llm", action="store_true", help="also run the Claude judge (needs ANTHROPIC_API_KEY)")
    p.add_argument("--model", default=None, help="model for --llm (default: claude-sonnet-5-5)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"skillscan {__version__}")
    return p


def main(argv: List[str] = None) -> int:
    args = build_parser().parse_args(argv)
    min_sev = Severity.parse(args.min_severity)

    roots: List[Path] = []
    for raw in args.paths:
        p = Path(raw)
        if not p.exists():
            print(f"skillscan: no such path: {raw}", file=sys.stderr)
            return 2
        roots.extend(find_skills(p))

    reports = [scan_skill(r) for r in roots]

    if args.llm:
        from . import llm
        for rep, root in zip(reports, roots):
            try:
                verdict, findings = llm.judge(skill_bundle_text(root), **({"model": args.model} if args.model else {}))
            except llm.LLMUnavailable as e:
                print(f"skillscan: --llm unavailable: {e}", file=sys.stderr)
                return 2
            except Exception as e:  # network/API errors should not hide static results
                print(f"skillscan: LLM judge failed for {rep.name}: {e}", file=sys.stderr)
                continue
            rep.llm_verdict = verdict
            rep.findings.extend(findings)
            rep.findings.sort(key=lambda f: (-f.severity, f.file, f.line))

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        print(render_text(reports, color=sys.stdout.isatty() and not args.no_color, min_sev=min_sev))

    if args.fail_on != "NEVER":
        threshold = Severity.parse(args.fail_on)
        if any(r.max_severity is not None and r.max_severity >= threshold for r in reports):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
