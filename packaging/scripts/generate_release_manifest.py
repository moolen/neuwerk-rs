#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from common import load_target, validate_target


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a release manifest for image artifacts.")
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--provider",
        required=True,
        choices=("aws", "azure", "gcp", "qemu", "virtualbox"),
    )
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--git-revision", required=True)
    parser.add_argument("--artifact", action="append", default=[], help="Artifact path to include; may be repeated")
    parser.add_argument("--image-reference", help="Published image reference (AMI ID, image family, gallery version, file name)")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    _, target_data = load_target(target=args.target)
    errors = validate_target(target_data)
    if errors:
        raise SystemExit("\n".join(errors))

    artifact_entries = []
    for artifact in args.artifact:
        path = Path(artifact)
        if not path.exists():
            raise SystemExit(f"artifact does not exist: {path}")
        artifact_entries.append(
            {
                "path": str(path),
                "size": path.stat().st_size,
                "sha256": sha256(path),
            }
        )

    payload = {
        "release_version": args.release_version,
        "git_revision": args.git_revision,
        "provider": args.provider,
        "target": target_data,
        "image_reference": args.image_reference,
        "artifacts": artifact_entries,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
