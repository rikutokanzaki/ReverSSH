from __future__ import annotations

import argparse
import logging
import re
import subprocess
from pathlib import Path

FROM_PATTERN = re.compile(r"^\s*FROM\s+([^\s]+)", re.MULTILINE)
LOGGER = logging.getLogger("docker-image-audit")


def tracked_dockerfiles() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "*Dockerfile*"],
        check=True,
        capture_output=True,
        text=True,
    )

    return [Path(path) for path in result.stdout.splitlines() if path]


def docker_images(dockerfile: Path) -> list[str]:
    content = dockerfile.read_text(encoding="utf-8")
    return FROM_PATTERN.findall(content)


def report_name(dockerfile: Path) -> str:
    return str(dockerfile).replace("/", "_").replace("\\", "_").replace(".", "_")


def image_report_name(image: str) -> str:
    return re.sub(r"[/:@.]", "_", image)


def run_trivy(arguments: list[str]) -> bool:
    result = subprocess.run(["trivy", *arguments], check=False)

    if result.returncode != 0:
        LOGGER.error("Trivy failed with exit code %s: %s", result.returncode, arguments)
        return False

    return True


def scan_dockerfiles(report_directory: Path) -> bool:
    scan_failed = False

    for dockerfile in tracked_dockerfiles():
        dockerfile_name = report_name(dockerfile)
        LOGGER.info("Scanning %s", dockerfile)

        if not run_trivy(
            [
                "config",
                "--severity",
                "HIGH,CRITICAL",
                "--format",
                "json",
                "--output",
                str(report_directory / f"{dockerfile_name}.config.json"),
                str(dockerfile),
            ]
        ):
            scan_failed = True

        for image in docker_images(dockerfile):
            if not run_trivy(
                [
                    "image",
                    "--severity",
                    "HIGH,CRITICAL",
                    "--format",
                    "json",
                    "--output",
                    str(
                        report_directory
                        / f"{dockerfile_name}.{image_report_name(image)}.image.json"
                    ),
                    image,
                ]
            ):
                scan_failed = True
    return scan_failed


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("--report-directory", type=Path, required=True)
    args = parser.parse_args()
    args.report_directory.mkdir(parents=True, exist_ok=True)

    if scan_dockerfiles(args.report_directory):
        LOGGER.error("One or more Trivy scans failed.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
