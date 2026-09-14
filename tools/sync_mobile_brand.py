#!/usr/bin/env python3
"""Copy the approved, already-generated elo icons into initialized mobile projects."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
TAURI = ROOT / "apps/desktop/src-tauri"


def main() -> None:
    copied = 0
    for platform, destination in (
        ("android", TAURI / "gen/android/app/src/main/res"),
        ("ios", TAURI / "gen/apple/Assets.xcassets/AppIcon.appiconset"),
    ):
        if not destination.is_dir():
            raise SystemExit(f"Initialize the {platform} project before copying icons")
        source = TAURI / "icons" / platform
        for original in sorted(source.rglob("*")):
            if original.is_file():
                target = destination / original.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, target)
                copied += 1
    # The layered iOS icon opts out of automatic glass effects on the logo.
    # Keep the PNG asset catalog as the fallback for older iOS versions.
    shutil.copytree(
        TAURI / "icons/AppIcon.icon",
        TAURI / "gen/apple/AppIcon.icon",
        dirs_exist_ok=True,
    )
    print(f"Copied {copied} approved icon assets; original brandbook files unchanged.")


if __name__ == "__main__":
    main()
