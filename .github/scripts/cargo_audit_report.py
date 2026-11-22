from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

LOGGER = logging.getLogger("cargo-audit-report")


def write_summary(fixable: list[tuple[str, str]], unfixable: list[str]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")

    if not summary_path:
        return

    with open(summary_path, "a", encoding="utf-8") as file:
        file.write("## Cargo audit\n\n")

        if unfixable:
            file.write("### Reported only (no patched release)\n")
            file.writelines(f"- `{finding}`\n" for finding in unfixable)
            file.write("\n")

        if fixable:
            file.write("### Must fix\n")
            file.writelines(
                f"- `{finding}`; patched: `{patched}`\n" for finding, patched in fixable
            )
            file.write("\n")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)

    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))

    fixable = []
    unfixable = []

    for finding in report.get("vulnerabilities", {}).get("list", []):
        advisory = finding["advisory"]
        patched = finding.get("versions", {}).get("patched", [])
        target = f"{advisory['id']} ({advisory['package']})"

        if patched:
            fixable.append((target, ", ".join(patched)))
        else:
            unfixable.append(target)

    warnings = report.get("warnings", {})
    blocking_warnings = {
        kind: entries
        for kind, entries in warnings.items()
        if kind in {"unsound", "yanked"} and entries
    }
    write_summary(fixable, unfixable)

    if fixable or blocking_warnings:
        LOGGER.error("Fixable advisories found:")

        for finding, patched in fixable:
            LOGGER.error("%s; patched: %s", finding, patched)
        for kind, entries in blocking_warnings.items():
            LOGGER.error("Blocking %s warnings found: %s", kind, len(entries))
        return 1

    LOGGER.info("No advisories with an available patched release were found.")

    if unfixable:
        LOGGER.info("Unfixable advisories were retained in the report.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
