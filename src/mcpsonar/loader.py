"""Load and validate the YAML config into the :class:`Config` model.

Uses a YAML loader that does **not** treat ``on``/``off``/``yes``/``no`` as booleans, so a
webhook's ``on:`` key (and any similar bareword) is read as the string it obviously is. Only
``true``/``false`` remain booleans.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .models import Config
from .secretref import SecretRefError
from .secretref import check_config as check_references


class _BoolSafeLoader(yaml.SafeLoader):
    """SafeLoader with YAML 1.1's ``on/off/yes/no`` boolean footgun removed."""


# Drop the stock bool resolver (which matches on/off/yes/no) from every first-character
# bucket, then add back a strict one that only matches true/false.
_BoolSafeLoader.yaml_implicit_resolvers = {
    ch: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
    for ch, resolvers in _BoolSafeLoader.yaml_implicit_resolvers.items()
}
_BoolSafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


class ConfigError(Exception):
    """A config file problem worth reporting to the user without a stack trace."""


def parse_config_text(text: str) -> Config:
    """Parse YAML config from a string (used by the API import endpoint)."""
    raw = yaml.load(text, Loader=_BoolSafeLoader) or {}
    return Config.model_validate(raw)


def load_config(path: str | Path) -> Config:
    """Read ``path`` and return a validated :class:`Config`.

    Raises :class:`ConfigError` with an actionable message for the common operator mistakes
    (missing file, or a directory where a file was expected — the classic Docker bind-mount
    footgun where the host path didn't exist and Docker created an empty directory).
    """
    p = Path(path)
    if p.is_dir():
        raise ConfigError(
            f"config path '{p}' is a directory, not a file. This usually means a Docker "
            f"bind mount was created before the host config file existed. Create the file "
            f"first (cp config.example.yaml config.yaml), removing any empty '{p.name}' "
            f"directory, then start again."
        )
    if not p.exists():
        raise ConfigError(
            f"config file '{p}' not found. Create it, e.g. cp config.example.yaml config.yaml"
        )
    text = p.read_text(encoding="utf-8")
    raw = yaml.load(text, Loader=_BoolSafeLoader) or {}
    config = Config.model_validate(raw)
    for name, server in config.servers.items():
        try:
            check_references(server)
        except SecretRefError as exc:
            raise ConfigError(f"server '{name}': {exc}") from None
    return config
