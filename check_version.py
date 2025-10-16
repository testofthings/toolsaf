#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path


def get_git_version():
    """Get version from the latest Git tag."""
    try:
        version = subprocess.check_output(
            ["git", "describe", "--tags"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
        return version.lstrip("v")  # e.g. v1.2.3 → 1.2.3
    except subprocess.CalledProcessError:
        sys.exit("No git tag found. Did you forget to tag the release?")


def get_changelog_version(changelog_path="CHANGELOG.md"):
    """Extract the first version number from the CHANGELOG."""
    text = Path(changelog_path).read_text()
    # Match markdown headers like "## [1.2.3]" or "## 1.2.3"
    match = re.search(r"^##\s*\[?v?(\d+\.\d+\.\d+)\]?", text, re.MULTILINE)
    if not match:
        sys.exit("Could not find a version header in CHANGELOG.md")
    return match.group(1)


def main():
    git_version = get_git_version()
    changelog_version = get_changelog_version()

    if git_version != changelog_version:
        sys.exit(
            f"Version mismatch!\n"
            f"Git tag version: {git_version}\n"
            f"CHANGELOG version: {changelog_version}"
        )

    print(f"Version check passed — {git_version} matches CHANGELOG.md")


if __name__ == "__main__":
    main()
