from __future__ import annotations

import argparse
import json
import logging
import re
import subprocess
from pathlib import Path

FROM_PATTERN = re.compile(
    r"^\s*FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)"
    r"(?:\s+AS\s+([^\s]+))?",
    re.IGNORECASE | re.MULTILINE,
)
LOGGER = logging.getLogger("docker-image-audit")


def tracked_dockerfiles() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "*Dockerfile*"],
        check=True,
        capture_output=True,
        text=True,
    )

    return [Path(path) for path in result.stdout.splitlines() if path]


def docker_images(dockerfile: Path) -> list[tuple[str, str, bool]]:
    content = dockerfile.read_text(encoding="utf-8")
    stages = FROM_PATTERN.findall(content)
    last_stage = len(stages) - 1

    return [
        (image, stage_name or f"stage-{index}", index < last_stage)
        for index, (image, stage_name) in enumerate(stages)
    ]


def report_name(dockerfile: Path) -> str:
    return str(dockerfile).replace("/", "_").replace("\\", "_").replace(".", "_")


def image_report_name(image: str) -> str:
    return re.sub(r"[/:@.]", "_", image)


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
        LOGGER.error("Docker build failed with exit code %s: %s", result.returncode, dockerfile)
        return False
    return True


def scan_dockerfiles(report_directory: Path) -> bool:
    scan_failed = False
    manifest = []

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

        for image, stage_name, is_builder in docker_images(dockerfile):
            image_report = report_directory / (
                f"{dockerfile_name}.{image_report_name(image)}.stage-{stage_name}.image.json"
            )
            manifest.append(
                {
                    "dockerfile": str(dockerfile),
                    "image": image,
                    "stage": stage_name,
                    "is_builder": is_builder,
                    "scope": "base-image",
                    "blocking": False,
                    "report": str(image_report),
                }
            )
            if not run_trivy(
                [
                    "image",
                    "--severity",
                    "HIGH,CRITICAL",
                    "--format",
                    "json",
                    "--output",
                    str(image_report),
                    image,
                ]
            ):
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
        if not build_dockerfile(dockerfile, built_image):
            scan_failed = True
        elif not run_trivy(
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
    args = parser.parse_args()
    args.report_directory.mkdir(parents=True, exist_ok=True)

    if scan_dockerfiles(args.report_directory):
        LOGGER.error("One or more Trivy scans failed.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
