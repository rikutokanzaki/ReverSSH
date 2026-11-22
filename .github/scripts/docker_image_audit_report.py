#!/usr/bin/env python3
"""Generate the Docker audit summary and enforce the runtime image gate."""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

LOGGER = logging.getLogger("docker-image-audit-report")


def load_manifest(report_directory: Path) -> dict[str, dict]:
    manifest_path = report_directory / "scan-manifest.json"
    if not manifest_path.exists():
        return {}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {entry["report"]: entry for entry in manifest}


def aggregate(findings: list[tuple]) -> list[tuple]:
    grouped = {}
    for vuln_id, package, installed, fixed, source in findings:
        key = (vuln_id, package, installed, fixed)
        grouped.setdefault(key, set()).add(source)
    return [(*key, sorted(sources)) for key, sources in sorted(grouped.items())]


def collect_findings(
    report_directory: Path,
) -> tuple[list[tuple], list[tuple], list[tuple], list[tuple], list[dict]]:
    runtime_fixable = []
    builder_fixable = []
    runtime_unfixable = []
    builder_unfixable = []
    config_findings = []
    manifest = load_manifest(report_directory)

    for path in report_directory.glob("*.image.json"):
        report = json.loads(path.read_text(encoding="utf-8"))
        source = manifest.get(str(path), {})
        source_label = (
            f"{source.get('dockerfile', path)}"
            f" [{source.get('scope', source.get('stage', 'unknown'))}]"
            f"/{source.get('stage', 'unknown')}"
            f" ({source.get('image', 'unknown')})"
        )
        blocking = source.get("blocking", not source.get("is_builder", False))

        for result in report.get("Results", []):
            for finding in result.get("Vulnerabilities") or []:
                item = (
                    finding.get("VulnerabilityID", "unknown"),
                    finding.get("PkgName", "unknown"),
                    finding.get("InstalledVersion", "unknown"),
                    finding.get("FixedVersion") or "",
                    source_label,
                )
                if item[3]:
                    (runtime_fixable if blocking else builder_fixable).append(item)
                else:
                    (runtime_unfixable if blocking else builder_unfixable).append(
                        item
                    )

    for path in report_directory.glob("*.config.json"):
        report = json.loads(path.read_text(encoding="utf-8"))
        for result in report.get("Results", []):
            config_findings.extend(result.get("Misconfigurations") or [])

    return (
        aggregate(runtime_fixable),
        aggregate(builder_fixable),
        aggregate(runtime_unfixable),
        aggregate(builder_unfixable),
        config_findings,
    )


def write_group(file, title: str, findings: list[tuple], fixed: bool) -> None:
    if not findings:
        return
    file.write(f"### {title}\n")
    for vuln_id, package, installed, version, sources in findings:
        transition = f" -> {version}" if fixed else ""
        file.write(f"- `{vuln_id}` in `{package}` ({installed}{transition})\n")
        file.write(f"  - {', '.join(sources)}\n")
    file.write("\n")


def write_summary(
    runtime_fixable: list[tuple],
    builder_fixable: list[tuple],
    runtime_unfixable: list[tuple],
    builder_unfixable: list[tuple],
    config_findings: list[dict],
) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as file:
        file.write("## Docker image audit\n\n")
        file.write(
            "Trivy scans base images and the final image built from every tracked Dockerfile.\n\n"
        )
        write_group(
            file,
            "Fixable HIGH/CRITICAL vulnerabilities (CI gate)",
            runtime_fixable,
            True,
        )
        write_group(
            file,
            "Fixable HIGH/CRITICAL vulnerabilities in builder stages (informational)",
            builder_fixable,
            True,
        )
        write_group(
            file,
            "HIGH/CRITICAL vulnerabilities without a known fix",
            runtime_unfixable,
            False,
        )
        write_group(
            file,
            "Unfixed HIGH/CRITICAL vulnerabilities in builder stages (informational)",
            builder_unfixable,
            False,
        )
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

    (
        runtime_fixable,
        builder_fixable,
        runtime_unfixable,
        builder_unfixable,
        config_findings,
    ) = collect_findings(args.report_directory)
    write_summary(
        runtime_fixable,
        builder_fixable,
        runtime_unfixable,
        builder_unfixable,
        config_findings,
    )

    if runtime_fixable:
        LOGGER.error("Fixable HIGH/CRITICAL runtime image vulnerabilities found:")
        for vuln_id, package, installed, fixed, sources in runtime_fixable:
            LOGGER.error(
                "%s %s: %s -> %s (%s)",
                vuln_id,
                package,
                installed,
                fixed,
                ", ".join(sources),
            )
        return 1

    LOGGER.info(
        "No HIGH/CRITICAL runtime image vulnerabilities with a known fix were found."
    )
    if runtime_unfixable or builder_fixable or builder_unfixable:
        LOGGER.info(
            "Non-blocking findings retained: runtime-unfixed=%s, builder-fixable=%s, builder-unfixed=%s.",
            len(runtime_unfixable),
            len(builder_fixable),
            len(builder_unfixable),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
