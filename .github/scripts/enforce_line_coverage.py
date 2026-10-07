#!/usr/bin/env python3
"""Enforce the 100%-lines coverage gate from the lcov export's per-line records.

Why the gate reads the export instead of llvm-cov's summary: llvm-cov 22's
SUMMARY aggregation falsely reports missed lines while every line-level view
computed from the exact same profdata reports the files fully covered
(`llvm-cov show` text and html, the lcov export's DA records, the cobertura
export, and the JSON export's segment list). A faithful reimplementation of
LLVM's sortNestedRegions/combineRegions/buildSegmentsImpl + LineCoverageStats
over the exported regions also produces 0 missed lines. The divergence
reproduces on macOS arm64 and x86_64 and on ubuntu-latest, survives a clean
coverage target dir and codegen-units=1, and persists on the newest
available toolchain (cargo-llvm-cov 0.9.1 + rustc 1.99.0's llvm-tools).
Side-by-side evidence: https://github.com/rennf93/tower-guard-rs/pull/35#issuecomment-6038980718

So the per-line records are the ground truth and the summary is the artifact.
This gate keeps the exact semantics the summary gate had, with no softening:
fail closed on every abnormal input, require 100% of executable lines hit,
hide nothing, exclude nothing. The summary table stays in the workflow as an
informational printout only.
"""

import sys
from pathlib import Path


def fail(message: str) -> int:
    print(f"coverage gate: {message}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return fail("usage: enforce_line_coverage.py <lcov.info>")

    path = Path(argv[1])
    if not path.is_file():
        return fail(f"export {path} is missing; failing closed")
    raw = path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        return fail(f"export {path} is empty; failing closed")

    # line counts per file, merged defensively by max in case the writer
    # ever emits duplicate DA records for one line (any execution counts).
    per_file: dict[str, dict[int, int]] = {}
    current: dict[int, int] | None = None
    for line in raw.splitlines():
        if line.startswith("SF:"):
            current = per_file.setdefault(line[len("SF:"):], {})
        elif line.startswith("DA:"):
            if current is None:
                return fail(f"DA record outside an SF section ({line!r}); failing closed")
            fields = line[len("DA:"):].split(",")
            try:
                lineno = int(fields[0])
                count = int(fields[1])
            except (IndexError, ValueError):
                return fail(f"unparseable DA record {line!r}; failing closed")
            current[lineno] = max(count, current.get(lineno, 0))
        elif line.startswith("end_of_record"):
            current = None

    if not per_file:
        return fail("export carries no SF sections; failing closed")
    total = sum(len(lines) for lines in per_file.values())
    if total == 0:
        return fail("export carries no DA line records; failing closed")

    missed_total = 0
    for name in sorted(per_file):
        lines = per_file[name]
        missed = sorted(lineno for lineno, count in lines.items() if count == 0)
        missed_total += len(missed)
        hit = len(lines) - len(missed)
        pct = 100.0 * hit / len(lines)
        detail = "" if not missed else f"  MISSED LINES {missed}"
        print(f"{name}  {hit}/{len(lines)} lines  {pct:.2f}%{detail}")

    covered = total - missed_total
    print(f"TOTAL  {covered}/{total} executable lines  {100.0 * covered / total:.2f}%")
    if missed_total:
        return fail(f"{missed_total} executable line(s) uncovered; failing")
    print("coverage gate: 100% of executable lines are hit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
