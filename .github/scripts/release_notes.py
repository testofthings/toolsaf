"""Release notes from the "Release notes" section of pull request descriptions

Usage:
  release_notes.py check                  Check the PR description in PR_BODY has release notes
  release_notes.py collect <from> <to>    Print release notes of the PRs merged between two git refs
"""

import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

SECTION_TITLE = "Release notes"
SECTION = re.compile(r"^##\s+release notes\s*$", re.IGNORECASE)
# The section ends at the next level 1 or 2 heading, or a thematic break like a "---" line before bot-generated sections
SECTION_END = re.compile(r"^(#{1,2}\s|\s{0,3}(-{3,}|\*{3,}|_{3,})\s*$)")
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def extract(body: Optional[str]) -> str:
    """Extract the release notes section from a PR description, empty if missing"""
    notes: List[str] = []
    found = False
    for line in COMMENT.sub("", body or "").splitlines():
        if found and SECTION_END.match(line):
            break
        if found:
            notes.append(line)
        else:
            found = bool(SECTION.match(line))
    return "\n".join(notes).strip()


def check() -> int:
    """Check the PR description has non-empty release notes"""
    if extract(os.environ.get("PR_BODY")):
        print(f"Found '{SECTION_TITLE}' section")
        return 0
    print(f"::error::Add a '## {SECTION_TITLE}' section to the PR description. "
          "It is published as the release notes of the release this PR creates.")
    return 1


def git(*args: str) -> str:
    """Run git and return its output"""
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


def merged_pulls(repository: str, sha: str) -> List[Dict[str, Any]]:
    """Return the PRs merged to the default branch that contain the commit"""
    output = subprocess.run(
        ["gh", "api", f"repos/{repository}/commits/{sha}/pulls"],
        check=True, capture_output=True, text=True).stdout
    return [pull for pull in json.loads(output)
            if pull["merged_at"] and pull["base"]["ref"] == pull["base"]["repo"]["default_branch"]]


def collect(start: str, end: str) -> int:
    """Print release notes of the PRs merged between two git refs"""
    repository = os.environ["GITHUB_REPOSITORY"]
    pulls: Dict[int, Dict[str, Any]] = {}
    other_commits: List[str] = []
    for sha in git("rev-list", "--reverse", f"{start}..{end}").splitlines():
        found = merged_pulls(repository, sha)
        for pull in found:
            pulls[pull["number"]] = pull
        if not found:
            other_commits.append(f"- {git('log', '-1', '--format=%s', sha)} ({sha[:7]})")

    for pull in sorted(pulls.values(), key=lambda p: str(p["merged_at"])):
        print(f"### {pull['title']} (#{pull['number']})\n")
        print(f"{extract(pull['body']) or '- No release notes given'}\n")
    if other_commits:
        print("### Other changes\n")
        print("\n".join(other_commits) + "\n")
    return 0


def main() -> int:
    """Entry point"""
    if sys.argv[1:] == ["check"]:
        return check()
    if len(sys.argv) == 4 and sys.argv[1] == "collect":
        return collect(sys.argv[2], sys.argv[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
