"""Parametrized schema-validation tests: every fixture is an independent item.

- test_schema_is_valid_draft7: schema/config.schema.json is a valid draft-07 schema.
- test_root_config: the repo's root-level example configs per validate.EXPECTED.
- test_schema_case: every generated fixture from cases.py.
"""

import pytest
from cases import CASES, Case
from jsonschema import Draft7Validator
from validate import EXPECTED, load_root_config, load_schema_validator, schema_violations, to_document


@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    return load_schema_validator()


def test_schema_is_valid_draft7() -> None:
    load_schema_validator()


def assert_result(name: str, errors: list[str], expect_pass: bool) -> None:
    passed = not errors
    assert passed == expect_pass, (
        f"{name}: expected {'pass' if expect_pass else 'fail'}, got {'pass' if passed else 'fail'}\n"
        + "\n".join(f"  at {error}" for error in errors)
    )


@pytest.mark.parametrize("name,expect_pass", sorted(EXPECTED.items()))
def test_root_config(validator: Draft7Validator, name: str, expect_pass: bool) -> None:
    assert_result(name, schema_violations(validator, load_root_config(name)), expect_pass)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_schema_case(validator: Draft7Validator, case: Case) -> None:
    assert_result(case.name, schema_violations(validator, to_document(case.build())), case.expect_pass)
