"""Validation engine for the afl-cassowire config JSON Schema.

The unit under test is a YAML document. Fixture builders (cases.py) produce
Python objects (or raw YAML text); validate.to_document() turns them into
parsed documents - the same text -> parse -> normalize -> validate pipeline a
real config file goes through - and Draft7Validator checks them.

Root-level example configs (default.yaml, default.qemu.yaml) are validated
from the repository per the EXPECTED table below. The former root-level
test_config*.yaml fixtures were dissolved: their distinctive content moved
into cases.py, the rest was duplicated by existing cases, and the files
themselves were renamed to test_config*.yaml.del at the repository root.

Run the sweep with `uv run pytest` (see test_schema_validate.py); runtime
dependencies (pyyaml, jsonschema) are declared in pyproject.toml and installed
by `uv sync`.
"""

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = REPO_ROOT / "schema" / "config.schema.json"

EXPECTED: dict[str, bool] = {
    "default.yaml": True,
    "default.qemu.yaml": True,
}


def normalize(node: Any) -> Any:
    # PyYAML decodes !!binary scalars to bytes; yaml-cpp hands the loader a
    # tagged scalar. JSON Schema cannot see YAML tags, so normalize bytes to
    # strings the way editors (which validate against this schema) perceive them.
    if isinstance(node, bytes):
        return node.decode("latin-1")
    if isinstance(node, dict):
        return {normalize(key): normalize(value) for key, value in node.items()}
    if isinstance(node, list):
        return [normalize(value) for value in node]
    return node


def load_schema_validator(schema_path: Path = SCHEMA_PATH) -> Draft7Validator:
    """Load the JSON Schema, assert it is a valid draft-07 schema, return a validator."""
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def to_document(instance: Any) -> Any:
    """Turn a case-builder result into a parsed YAML document.

    str results are taken verbatim as YAML text (needed for syntax that a dump
    cannot preserve, e.g. an unquoted `<<` merge key); anything else is
    serialized with yaml.safe_dump first.
    """
    text = instance if isinstance(instance, str) else yaml.safe_dump(instance, sort_keys=False)
    return normalize(yaml.safe_load(text))


def load_root_config(name: str) -> Any:
    """Parse a root-level example config from the repository."""
    with open(REPO_ROOT / name, encoding="utf-8") as handle:
        return normalize(yaml.safe_load(handle))


def schema_violations(validator: Draft7Validator, instance: Any) -> list[str]:
    """Return all schema violations, sorted, as "<location>: <message>" strings."""
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda err: (list(map(str, err.absolute_path)), err.message),
    )
    return [f"{'/'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}" for error in errors]
