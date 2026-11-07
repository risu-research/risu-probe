"""Single-project RISU Probe configuration loader (no execution on import)."""
from __future__ import annotations
import json
import sys
from pathlib import Path

class ConfigError(Exception):
    pass


def resolve_config(path: str) -> tuple[Path, dict]:
    candidate = Path(path).expanduser().resolve()
    if candidate.is_dir():
        candidate /= 'risu-probe.json'
    try:
        content = candidate.read_text(encoding='utf-8')
    except OSError as e:
        raise ConfigError(f'configuration not found/readable: {candidate}') from e
    try:
        config = json.loads(content)
    except (TypeError, ValueError) as e:
        raise ConfigError('invalid JSON configuration') from e
    if not isinstance(config, dict) or config.get('version') != 1:
        raise ConfigError('project configuration must be object with version: 1')
    return candidate, config


def load_cases(config_file: Path, config: dict) -> tuple[list, Path]:
    if 'cases' in config:
        value = config['cases']
        origin = config_file
    elif 'cases_file' in config:
        target = config_file.parent / str(config['cases_file'])
        try:
            value = json.loads(target.read_text(encoding='utf-8'))
        except (OSError, ValueError) as e:
            raise ConfigError(f'could not read cases from {target}') from e
        origin = target
        if isinstance(value, dict):
            value = value.get('cases')
    else:
        raise ConfigError('configuration requires cases or cases_file')
    if not isinstance(value, list) or not value or not all(isinstance(v, dict) for v in value):
        raise ConfigError('cases must be a nonempty list of objects')
    return value, origin


def resolve_argv(config_file: Path, config: dict) -> list[str] | None:
    raw = config.get('server_cmd')
    if raw is None:
        return None
    if not isinstance(raw, list) or not raw or not all(isinstance(v, str) and v for v in raw):
        raise ConfigError('server_cmd must be an argv array of strings; shell syntax unsupported')
    return [v.replace('{python}', sys.executable).replace('{project}', str(config_file.parent)) for v in raw]
