"""Locate or safely materialize the bundled AI-agent workflow skill."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

AGENT_SKILL_NAME = "remove-text-watermarks"
AGENT_SKILL_FILES = ("SKILL.md", "agents/openai.yaml")


def _read_skill_file(relative_path: str) -> bytes:
    resource = files("dewatermark").joinpath("skills").joinpath(AGENT_SKILL_NAME)
    for part in relative_path.split("/"):
        resource = resource.joinpath(part)
    try:
        return resource.read_bytes()
    except FileNotFoundError:
        source = Path(__file__).resolve().parents[2] / "skills" / AGENT_SKILL_NAME
        return (source / relative_path).read_bytes()


def agent_skill_path() -> Path:
    """Return the installed skill directory when resources are filesystem-backed."""
    resource = files("dewatermark").joinpath("skills").joinpath(AGENT_SKILL_NAME)
    candidate = Path(str(resource))
    if candidate.is_dir() and all((candidate / item).is_file() for item in AGENT_SKILL_FILES):
        return candidate.resolve()
    source = Path(__file__).resolve().parents[2] / "skills" / AGENT_SKILL_NAME
    if source.is_dir() and all((source / item).is_file() for item in AGENT_SKILL_FILES):
        return source.resolve()
    raise RuntimeError("bundled agent skill is not available as a persistent filesystem path")


def materialize_agent_skill(destination: Path | str) -> tuple[Path, ...]:
    """Copy the bundled skill to a new directory, refusing every overwrite."""
    target = Path(destination)
    if target.exists() or target.is_symlink():
        raise FileExistsError("agent skill destination already exists")
    target.mkdir(parents=True, exist_ok=False)
    created: list[Path] = []
    for relative_path in AGENT_SKILL_FILES:
        output = target.joinpath(*relative_path.split("/"))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(_read_skill_file(relative_path))
        created.append(output)
    return tuple(created)


__all__ = [
    "AGENT_SKILL_FILES",
    "AGENT_SKILL_NAME",
    "agent_skill_path",
    "materialize_agent_skill",
]
