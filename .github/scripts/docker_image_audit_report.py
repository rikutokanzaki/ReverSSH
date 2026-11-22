from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

LOGGER = logging.getLogger("docker-image-audit-report")


def collect_findings(
    report_directory: Path,
) -> tuple[list[tuple], list[tuple], list[dict]]:
    fixable = []
    unfixable = []
    config_findings = []

    for path in report_directory.glob("*.image.json"):
        report = json.loads(path.read_text(encoding="utf-8"))

        for result in report.get("Results", []):
            for finding in result.get("Vulnerabilities") or []:
                item = (
                    finding.get("VulnerabilityID", "unknown"),
                    finding.get("PkgName", "unknown"),
                    finding.get("InstalledVersion", "unknown"),
                    finding.get("FixedVersion") or "",
                    str(path),
                )
                (fixable if item[3] else unfixable).append(item)

    for path in report_directory.glob("*.config.json"):
        report = json.loads(path.read_text(encoding="utf-8"))
        for result in report.get("Results", []):
            config_findings.extend(result.get("Misconfigurations") or [])

    return fixable, unfixable, config_findings


def write_summary(
    fixable: list[tuple], unfixable: list[tuple], config_findings: list[dict]
) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")

    if not summary_path:
        return

    with open(summary_path, "a", encoding="utf-8") as file:
        file.write("## Docker image audit\n\n")
        file.write("Trivy scans every `FROM` image in tracked Dockerfiles.\n\n")

        if fixable:
            file.write("### Fixable HIGH/CRITICAL vulnerabilities\n")
            file.writelines(
                f"- `{vuln_id}` in `{package}` ({installed} -> {fixed}); `{source}`\n"
                for vuln_id, package, installed, fixed, source in fixable
            )
            file.write("\n")

        if unfixable:
            file.write("### HIGH/CRITICAL vulnerabilities without a known fix\n")
            file.writelines(
                f"- `{vuln_id}` in `{package}` ({installed}); `{source}`\n"
                for vuln_id, package, installed, _, source in unfixable
            )
            file.write("\n")

        if config_findings:
            file.write(
                f"### Dockerfile findings (informational: {len(config_findings)})\n\n"
            )
            file.writelines(
                f"- `{finding.get('ID', 'unknown')}`: {finding.get('Title', 'unknown')}\n"
                for finding in config_findings
            )


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("--report-directory", type=Path, required=True)

    args = parser.parse_args()
    fixable, unfixable, config_findings = collect_findings(args.report_directory)

    write_summary(fixable, unfixable, config_findings)

    if fixable:
        LOGGER.error("Fixable HIGH/CRITICAL Docker image vulnerabilities found:")

        for vuln_id, package, installed, fixed, source in fixable:
            LOGGER.error(
                "%s %s: %s -> %s (%s)", vuln_id, package, installed, fixed, source
            )

        return 1

    LOGGER.info(
        "No HIGH/CRITICAL Docker image vulnerabilities with a known fix were found."
    )

    if unfixable:
        LOGGER.info(
            "%s finding(s) without a known fix were retained in the reports.",
            len(unfixable),
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
