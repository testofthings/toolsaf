import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, Union, List


FILE_PATH = Path(__file__)
STATEMENTS_PATH = FILE_PATH.parent / "statements"
GITHUB_SUMMARY = os.environ.get('GITHUB_STEP_SUMMARY', None)


def read_setup(setup_file_path: Path) -> List[Dict[str, Union[str, List[str]]]]:
    """Read test setup json"""
    with setup_file_path.open("rb") as file:
        setup = json.load(file)
    return setup["statements"]


def create_statements_dir() -> None:
    """Create directory for statements if it does not already exist"""
    if not os.path.isdir(STATEMENTS_PATH):
        print("Creating statements directory")
        os.mkdir(STATEMENTS_PATH)


def pull_or_clone_repository(url: str) -> None:
    """Pull if already cloned; clone otherwise"""
    repository_name = url.split("/")[-1]
    repo_path = STATEMENTS_PATH / repository_name
    if repo_path.exists():
        print(f"Pulling latest {repository_name}")
        subprocess.run(
            ["git", "pull"],
            check=True,
            cwd=repo_path
        )
    else:
        subprocess.run(
            ["git", "clone", url],
            check=True,
            cwd=STATEMENTS_PATH
        )


def run_statement(url: str, product: str) -> None:
    """Run statement, exit with error code on failure"""
    dir_name = url.split("/")[-1]
    try:
        subprocess.run(
            ["python", f"{dir_name}/{product}/statement.py"],
            capture_output=True,
            text=True,
            check=True,
            cwd=STATEMENTS_PATH
        )
        print(f"{dir_name} run passed")
        if GITHUB_SUMMARY:
            summarize_passed(dir_name)
    except subprocess.CalledProcessError as e:
        print(f"{dir_name} run failed! Error was:")
        print(e.stderr)
        if GITHUB_SUMMARY:
            summarize_failed(dir_name, str(e.stderr))
        sys.exit(1)


def summarize_passed(statement: str) -> None:
    add_to_summary(
        f"### {statement}",
        "Status: **Passed**"
    )


def summarize_failed(statement: str, error: str) -> None:
    add_to_summary(
        f"### {statement}",
        "Status: **Failed**",
        "Error was:",
        f"```{error}```"
    )


def add_to_summary(*text: str) -> None:
    with open(GITHUB_SUMMARY, 'a') as f:
        for line in text:
            print(line, file=f)


def process_entry(entry: Dict[str, Union[str, List[str]]]) -> None:
    """Process a single entry from the setup"""
    pull_or_clone_repository(entry["url"])
    run_statement(entry["url"], entry["product"])


def main(setup_file_path_str: str) -> None:
    """Perform test"""
    setup = read_setup(Path(setup_file_path_str))
    create_statements_dir()
    if GITHUB_SUMMARY:
        add_to_summary("# Test Summary:")
    for entry in setup:
        process_entry(entry)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {FILE_PATH.name} <path_to_setup_json_file>")
    else:
        main(sys.argv[1])
        sys.exit(0)
