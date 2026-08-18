from pathlib import Path

import pytest

from dewatermark.agent_skill import (
    AGENT_SKILL_FILES,
    agent_skill_path,
    materialize_agent_skill,
)


def test_agent_skill_path_contains_complete_workflow() -> None:
    path = agent_skill_path()
    assert path.name == "remove-text-watermarks"
    assert all((path / relative).is_file() for relative in AGENT_SKILL_FILES)


def test_materialize_agent_skill_is_complete_and_refuses_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "remove-text-watermarks"
    created = materialize_agent_skill(destination)
    assert {path.relative_to(destination).as_posix() for path in created} == set(AGENT_SKILL_FILES)
    assert (destination / "SKILL.md").read_text(encoding="utf-8").startswith("---\nname:")
    with pytest.raises(FileExistsError, match="destination already exists"):
        materialize_agent_skill(destination)
