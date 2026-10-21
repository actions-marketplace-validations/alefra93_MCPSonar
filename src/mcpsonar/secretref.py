"""Secret references: keep credentials out of the configuration and the database.

A header or stdio ``env`` value may contain references, resolved at **check time** and
never stored, exported or shown resolved::

    headers: { Authorization: "Bearer ${env:MCPSONAR_SECRET_GITHUB}" }
    env:     { API_KEY: "${file:/run/secrets/brave_api_key}" }

* ``${env:NAME}`` — an environment variable of the mcpsonar process.
* ``${file:PATH}`` — the content of a file (absolute path; one trailing newline removed),
  re-read on every check, so a rotated secret is picked up without a restart.

**What a reference may read is allowlisted.** A configuration can come from the API (anyone
with a write token) or from a shared file. Without a limit, ``${file:/root/.ssh/id_rsa}``
or ``${env:AWS_SECRET_ACCESS_KEY}`` would be read and sent, as a header, to a server chosen
by whoever wrote the configuration. So:

* environment variables must be named ``MCPSONAR_SECRET_*``, or be listed (comma-separated)
  in ``MCPSONAR_SECRET_ENV``;
* files must be inside ``/run/secrets`` (Docker and Kubernetes secrets) or one of the
  directories in ``MCPSONAR_SECRETS_DIR`` (separated by the OS path separator), after
  symlinks are resolved.

The allowlist is read from mcpsonar's own environment: only whoever starts mcpsonar can
widen it.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path

from .models import ServerConfig

ENV_PREFIX = "MCPSONAR_SECRET_"
ENV_ALLOW_VAR = "MCPSONAR_SECRET_ENV"
DIRS_VAR = "MCPSONAR_SECRETS_DIR"
DEFAULT_DIRS = ("/run/secrets",)
MAX_FILE_BYTES = 64 * 1024

_REF = re.compile(r"\$\{(?P<kind>env|file):(?P<target>[^{}]+)\}")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# What may surround a reference in a value that is still safe to show (e.g. "Bearer <ref>").
_SHOWABLE_REST = {"", "bearer", "basic", "token"}


class SecretRefError(ValueError):
    """A reference is malformed, not allowed, or cannot be resolved. The message names the
    reference, never a secret value."""


def has_references(value: str) -> bool:
    return "${" in value


def check_syntax(value: str) -> None:
    """Every ``${`` must start a well-formed ``${env:NAME}`` or ``${file:PATH}``."""
    pos = 0
    while (start := value.find("${", pos)) != -1:
        match = _REF.match(value, start)
        if match is None:
            raise SecretRefError(
                f"invalid reference at '{value[start:start + 40]}': use ${{env:NAME}} or "
                "${file:/absolute/path}")
        kind, target = match["kind"], match["target"]
        if kind == "env" and not _ENV_NAME.match(target):
            raise SecretRefError(f"invalid environment variable name in '{match[0]}'")
        if kind == "file" and not _is_absolute(target):
            raise SecretRefError(f"'{match[0]}': the path must be absolute")
        pos = match.end()


def _is_absolute(target: str) -> bool:
    return Path(target).is_absolute() or target.startswith("/")


def showable(value: str) -> bool:
    """True if ``value`` holds references and nothing secret around them, so the API can
    show it as-is (``${env:X}``, ``Bearer ${env:X}``) instead of masking it."""
    if not has_references(value):
        return False
    try:
        check_syntax(value)
    except SecretRefError:
        return False
    return _REF.sub("", value).strip().lower() in _SHOWABLE_REST


def _allowed_env(name: str, environ: Mapping[str, str]) -> bool:
    listed = {n.strip() for n in environ.get(ENV_ALLOW_VAR, "").split(",") if n.strip()}
    return name.startswith(ENV_PREFIX) or name in listed


def secret_dirs(environ: Mapping[str, str] | None = None) -> list[Path]:
    environ = os.environ if environ is None else environ
    extra = [d for d in environ.get(DIRS_VAR, "").split(os.pathsep) if d.strip()]
    return [Path(d) for d in (*DEFAULT_DIRS, *extra)]


def _allowed_file(target: str, environ: Mapping[str, str]) -> Path:
    path = Path(target).resolve()  # symlinks and ".." resolved before the check
    for directory in secret_dirs(environ):
        if path.is_relative_to(directory.resolve()):
            return path
    allowed = ", ".join(str(d) for d in secret_dirs(environ))
    raise SecretRefError(
        f"'${{file:{target}}}' is outside the secret directories ({allowed}); add its "
        f"directory to {DIRS_VAR}")


def check_policy(value: str, environ: Mapping[str, str] | None = None) -> None:
    """Syntax and allowlist only: the variable or file need not exist yet."""
    environ = os.environ if environ is None else environ
    check_syntax(value)
    for match in _REF.finditer(value):
        if match["kind"] == "env" and not _allowed_env(match["target"], environ):
            raise SecretRefError(
                f"'{match[0]}' is not allowed: name the variable {ENV_PREFIX}* or list it in "
                f"{ENV_ALLOW_VAR}")
        if match["kind"] == "file":
            _allowed_file(match["target"], environ)


def _read_file(target: str, environ: Mapping[str, str]) -> str:
    path = _allowed_file(target, environ)
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        raise SecretRefError(f"'${{file:{target}}}': file not found") from None
    except OSError as exc:
        raise SecretRefError(f"'${{file:{target}}}': cannot be read ({exc.strerror})") from None
    if len(data) > MAX_FILE_BYTES:
        raise SecretRefError(f"'${{file:{target}}}': larger than {MAX_FILE_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SecretRefError(f"'${{file:{target}}}': not UTF-8 text") from None
    return text.removesuffix("\n").removesuffix("\r")


def resolve_value(value: str, environ: Mapping[str, str] | None = None) -> str:
    environ = os.environ if environ is None else environ
    check_policy(value, environ)

    def one(match: re.Match[str]) -> str:
        if match["kind"] == "env":
            if match["target"] not in environ:
                raise SecretRefError(f"'{match[0]}': environment variable not set")
            return environ[match["target"]]
        return _read_file(match["target"], environ)

    return _REF.sub(one, value)


def check_config(cfg: ServerConfig, environ: Mapping[str, str] | None = None) -> None:
    """Early feedback (API, config files): every reference is well-formed and allowed."""
    for where, values in (("header", cfg.headers), ("env", cfg.env)):
        for key, value in values.items():
            try:
                check_policy(value, environ)
            except SecretRefError as exc:
                raise SecretRefError(f"{where} '{key}': {exc}") from None


def resolve(cfg: ServerConfig, environ: Mapping[str, str] | None = None) -> ServerConfig:
    """``cfg`` with every reference replaced by its value, for one check. The result must
    never be stored or shown; ``cfg`` itself is returned when it has no references."""
    if not any(has_references(v) for v in (*cfg.headers.values(), *cfg.env.values())):
        return cfg
    headers, env = {}, {}
    for out, where, values in ((headers, "header", cfg.headers), (env, "env", cfg.env)):
        for key, value in values.items():
            try:
                out[key] = resolve_value(value, environ) if has_references(value) else value
            except SecretRefError as exc:
                raise SecretRefError(f"{where} '{key}': {exc}") from None
            if where == "header" and ("\r" in out[key] or "\n" in out[key]):
                raise SecretRefError(f"header '{key}': the resolved value has a line break")
    return cfg.model_copy(update={"headers": headers, "env": env})
