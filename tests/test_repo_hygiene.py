import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
ACTION_REFERENCE = re.compile(r"^\s*(?:-\s+)?uses:\s+([^\s#]+)")


def test_generated_and_private_outputs_are_excluded_from_build_context():
    patterns = set((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())
    required = {
        ".env",
        ".env.*",
        "node_modules",
        "integrations/jetbrains/.gradle",
        "integrations/jetbrains/.intellijPlatform",
        "integrations/vscode/*.vsix",
        "progress.jsonl",
        "reference-run",
        "evidence",
    }
    assert required <= patterns


def test_environment_variants_are_git_ignored_but_example_template_is_allowed():
    patterns = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in patterns
    assert ".env.*" in patterns
    assert "!.env.example" in patterns
    assert patterns.index("!.env.example") > patterns.index(".env.*")


def test_external_github_actions_are_commit_pinned():
    action_files = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    action_files.append(ROOT / "action.yml")
    for path in action_files:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = ACTION_REFERENCE.match(line)
            if match is None:
                continue
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), (
                f"external action is not commit-pinned: {path}:{line_number}: {reference}"
            )


def test_action_treats_paths_as_literal_array_items():
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert 'paths+=("$path")' in action
    assert '-- "${paths[@]}"' in action
    assert "-- $INPUT_PATHS" not in action
