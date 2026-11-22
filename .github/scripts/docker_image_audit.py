from __future__ import annotations

import argparse
import json
import logging
import re
import subprocess
from pathlib import Path

LOGGER = logging.getLogger("docker-image-audit")


def tracked_dockerfiles() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "*Dockerfile*"],
        check=True,
        capture_output=True,
        text=True,
    )

    return [Path(path) for path in result.stdout.splitlines() if path]


def report_name(dockerfile: Path) -> str:
    return str(dockerfile).replace("/", "_").replace("\\", "_").replace(".", "_")


def audit_image_name(dockerfile: Path) -> str:
    name = re.sub(r"[^a-zA-Z0-9_.-]", "-", str(dockerfile).replace("\\", "-"))
    return f"reverssh-security-audit-{name.lower()}:local"


def run_trivy(arguments: list[str]) -> bool:
    result = subprocess.run(["trivy", *arguments], check=False)

    if result.returncode != 0:
        LOGGER.error("Trivy failed with exit code %s: %s", result.returncode, arguments)
        return False

    return True


def build_dockerfile(dockerfile: Path, image: str) -> bool:
    result = subprocess.run(
        [
            "docker",
            "build",
            "--pull",
            "--file",
            str(dockerfile),
            "--tag",
            image,
            ".",
        ],
        check=False,
    )
    if result.returncode != 0:
        LOGGER.error(
            "Docker build failed with exit code %s: %s", result.returncode, dockerfile
        )
        return False
    return True


def scan_dockerfiles(report_directory: Path, ignore_file: Path | None) -> bool:
    scan_failed = False
    manifest = []

    for dockerfile in tracked_dockerfiles():
        dockerfile_name = report_name(dockerfile)
        LOGGER.info("Scanning %s", dockerfile)

        config_arguments = [
            "config",
            "--severity",
            "HIGH,CRITICAL",
            "--format",
            "json",
            "--output",
            str(report_directory / f"{dockerfile_name}.config.json"),
        ]
        manifest.append(
            {
                "type": "config",
                "dockerfile": str(dockerfile),
                "report": str(report_directory / f"{dockerfile_name}.config.json"),
            }
        )

        if ignore_file and ignore_file.exists():
            config_arguments.extend(["--ignorefile", str(ignore_file)])

        config_arguments.append(str(dockerfile))

        if not run_trivy(config_arguments):
            scan_failed = True

        built_image = audit_image_name(dockerfile)
        built_report = report_directory / f"{dockerfile_name}.final.image.json"
        manifest.append(
            {
                "dockerfile": str(dockerfile),
                "image": built_image,
                "stage": "final",
                "is_builder": False,
                "scope": "final-image",
                "blocking": True,
                "report": str(built_report),
            }
        )
        if not build_dockerfile(dockerfile, built_image) or not run_trivy(
            [
                "image",
                "--severity",
                "HIGH,CRITICAL",
                "--format",
                "json",
                "--output",
                str(built_report),
                built_image,
            ]
        ):
            scan_failed = True
    (report_directory / "scan-manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return scan_failed


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("--report-directory", type=Path, required=True)
    parser.add_argument("--ignore-file", type=Path)
    args = parser.parse_args()
    args.report_directory.mkdir(parents=True, exist_ok=True)

    if scan_dockerfiles(args.report_directory, args.ignore_file):
        LOGGER.error("One or more Trivy scans failed.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
