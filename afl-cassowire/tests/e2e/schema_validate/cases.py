"""Schema-validation fixtures, generated in Python (no yaml files on disk).

Every case is a `Case` entry below: a fixture name, the expected schema
result, and a builder. Most builders start from the shared valid blocks
(blocks.py) and apply a single mutation or exercise one YAML feature
(anchor/alias reuse, `!!binary`, a non-map root).

A builder returns the instance to validate:
  - a Python object (dict/list): serialized with `yaml.safe_dump` and
    re-parsed with `yaml.safe_load` by validate.to_document(), i.e. the same
    text -> parse -> normalize -> validate pipeline a real config file goes
    through. Referencing the same dict object twice in one config makes the
    serializer emit a YAML anchor + alias, like a hand-written config.
  - raw YAML text (str): used only where a dump/load round-trip cannot
    preserve the syntax. `yaml.safe_dump` emits the merge key quoted as
    `'<<'`, and a quoted merge key is NOT treated as a merge by safe_load
    (the implicit merge tag requires the plain unquoted `<<`), so the
    helper-anchors fixture must stay verbatim text.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from blocks import (
    afl_block,
    base_config,
    cleanup_block,
    network_block,
    payload_block,
    port_detection_block,
    target_block,
)


@dataclass(frozen=True)
class Case:
    """One schema-validation fixture: name, expectation, and builder."""

    name: str
    expect_pass: bool
    build: Callable[[], Any]


def _build_full() -> dict[str, Any]:
    # Every section populated.
    return {
        "target": target_block(
            args=["./target", "-g", "daemon off;"],
            env={"FOO": "bar"},
            env_preserve="all",
        ),
        "network": network_block(
            host="127.0.0.1",
            timeout_ms=200,
            initial_ms=200,
            probe=True,
            probe_retry_ms=5,
        ),
        "afl": afl_block(loop_count=50000, enable_cmplog=False, msg_log_level="error"),
        "port_detection": port_detection_block(primary="seccomp"),
        "cleanup": cleanup_block(enabled=True, on_port_conflict="error"),
        "payload": payload_block(
            prefix="GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            suffix=b"\r\n\r\n",
        ),
    }


def _build_binary_payload() -> dict[str, Any]:
    # payload values may be plain strings or !!binary tagged scalars
    # (JSON Schema sees tagged scalars as plain strings).
    return base_config(
        payload=payload_block(
            prefix=b"GET /test HTTP/1.1",
            suffix=b"\r\n\r\n",
        )
    )


def _build_cmplog_alias() -> dict[str, Any]:
    # enable_cmplog: true requires target_cmplog and network_cmplog.
    # Exercises the YAML anchor/alias reuse of the whole network section:
    # the same dict object is referenced twice, so the serializer emits
    # an anchor and an alias.
    net = network_block(host="127.0.0.1")
    return {
        "target": target_block(),
        "network": net,
        "afl": afl_block(enable_cmplog=True),
        "target_cmplog": target_block(binary="./target-cmplog"),
        "network_cmplog": net,
    }


def _build_cmplog_ignored_when_disabled() -> dict[str, Any]:
    # With enable_cmplog: false the cmplog sections are ignored and NOT validated
    # by the loader (config.cpp), so even a malformed cmplog target must pass here.
    return base_config(
        afl=afl_block(enable_cmplog=False),
        target_cmplog={"args": []},
        network_cmplog={"bogus_key": True},
    )


_HELPER_ANCHORS_YAML = """\
# Root keys starting with "__" are ignored by the loader and the schema.
# They anchor reusable fragments that real sections below reference via
# aliases (network: *net) or merge keys (<<: *t).
__helper_net: &net
  host: 127.0.0.1
  port: 8080
  timeout_ms: 500
  initial_ms: 5000

__helper_target: &t
  binary: /usr/sbin/nginx
  args:
    - /usr/sbin/nginx
    - -g
    - daemon off;

target:
  <<: *t

network: *net

afl:
  loop_count: 1000
"""


def _build_helper_anchors() -> str:
    # Raw text on purpose: an unquoted `<<` merge key cannot survive a
    # dump/load round-trip (safe_dump quotes it, which disables merging).
    return _HELPER_ANCHORS_YAML


def _build_cmplog_target_incomplete() -> dict[str, Any]:
    # With enable_cmplog: true the cmplog sections are fully validated:
    # target_cmplog without `binary` must be rejected.
    net = network_block()
    return {
        "target": target_block(),
        "network": net,
        "afl": afl_block(enable_cmplog=True),
        "target_cmplog": {"args": ["./target-cmplog"]},
        "network_cmplog": net,
    }


CASES: list[Case] = [
    # ------------------------------- must pass -------------------------------
    Case(
        "valid_minimal",
        True,
        # Bare minimum: only the required keys; everything else uses loader defaults.
        base_config,
    ),
    Case(
        "valid_full",
        True,
        _build_full,
    ),
    Case(
        "valid_binary_payload",
        True,
        _build_binary_payload,
    ),
    Case(
        "valid_payload_null",
        True,
        # A null payload section is accepted by the loader and treated as empty.
        lambda: base_config(payload=None),
    ),
    Case(
        "valid_cmplog_alias",
        True,
        _build_cmplog_alias,
    ),
    Case(
        "valid_cmplog_ignored_when_disabled",
        True,
        _build_cmplog_ignored_when_disabled,
    ),
    Case(
        "valid_helper_anchors",
        True,
        _build_helper_anchors,
    ),
    Case(
        "valid_cleanup_disabled",
        True,
        # Cleanup is opt-in; both keys together and disabled are valid.
        lambda: base_config(cleanup=cleanup_block(enabled=False)),
    ),
    Case(
        "valid_cleanup_kill_orphan",
        True,
        # Explicit opt-in to SIGKILLing orphaned holders of the configured port.
        lambda: base_config(cleanup=cleanup_block(enabled=True, on_port_conflict="kill_orphan")),
    ),
    Case(
        "valid_port_detection_verify_ownership",
        True,
        # port_detection.verify_ownership: true (default) - explicitly set for clarity.
        lambda: base_config(port_detection=port_detection_block(verify_ownership=True)),
    ),
    Case(
        "valid_port_detection_verify_ownership_false",
        True,
        # port_detection.verify_ownership: false - disables the procfs inode ownership check.
        lambda: base_config(port_detection=port_detection_block(verify_ownership=False)),
    ),
    # ------------------------------- must fail -------------------------------
    Case(
        "invalid_afl_loop_count_zero",
        False,
        # afl.loop_count must be > 0.
        lambda: base_config(afl=afl_block(loop_count=0)),
    ),
    Case(
        "invalid_afl_msg_log_level",
        False,
        # afl.msg_log_level must be a recognized log level name.
        lambda: base_config(afl=afl_block(msg_log_level="noisy")),
    ),
    Case(
        "invalid_cleanup_enabled_type",
        False,
        # cleanup.enabled is a strict boolean.
        lambda: base_config(cleanup=cleanup_block(enabled="yes")),
    ),
    Case(
        "invalid_cleanup_port_conflict",
        False,
        # on_port_conflict is a closed enum.
        lambda: base_config(cleanup=cleanup_block(on_port_conflict="kill_all")),
    ),
    Case(
        "invalid_cleanup_force_kill_removed",
        False,
        # force_kill_ms was removed (cleanup is SIGKILL-only).
        lambda: base_config(cleanup=cleanup_block(force_kill_ms=1000)),
    ),
    Case(
        "invalid_cmplog_sections_missing",
        False,
        # enable_cmplog: true requires target_cmplog and network_cmplog.
        lambda: base_config(afl=afl_block(enable_cmplog=True)),
    ),
    Case(
        "invalid_cmplog_target_incomplete",
        False,
        _build_cmplog_target_incomplete,
    ),
    Case(
        "invalid_defork_key_removed",
        False,
        # The defork key was removed with the ptrace/seccomp-trace port detection.
        lambda: base_config(port_detection=port_detection_block(primary="seccomp", defork=True)),
    ),
    Case(
        "invalid_kill_pattern_removed",
        False,
        # kill_pattern was removed in favor of the port-scoped cleanup policy.
        lambda: base_config(cleanup=cleanup_block(kill_pattern="nginx")),
    ),
    Case(
        "invalid_missing_network",
        False,
        # `network` is required at the root.
        lambda: {"target": target_block()},
    ),
    Case(
        "invalid_nested_helper_key",
        False,
        # The "__" helper exemption applies to the root only; nested sections
        # stay strict and must reject "__"-prefixed keys.
        lambda: {
            "target": target_block(binary="/usr/sbin/nginx", **{"__internal": "just a note"}),
            "network": network_block(),
        },
    ),
    Case(
        "invalid_network_port_missing",
        False,
        # port is required inside network.
        lambda: {"target": target_block(), "network": {"host": "127.0.0.1"}},
    ),
    Case(
        "invalid_network_port_string",
        False,
        # Strict scalar types: a quoted port is rejected even though yaml-cpp's
        # as<int> would tolerate it.
        lambda: base_config(network=network_block(port="8080")),
    ),
    Case(
        "invalid_network_port_too_large",
        False,
        # port is required and must be 1-65535 (from the former root-level
        # test_config_invalid_port.yaml fixture).
        lambda: base_config(network=network_block(port=99999)),
    ),
    Case(
        "invalid_network_port_zero",
        False,
        # port is required and must be 1-65535.
        lambda: {"network": network_block(port=0), "target": target_block()},
    ),
    Case(
        "invalid_network_probe_retry_negative",
        False,
        # probe_retry_ms must be >= 0.
        lambda: base_config(network=network_block(probe_retry_ms=-1)),
    ),
    Case(
        "invalid_network_timeout_zero",
        False,
        # timeout_ms must be > 0.
        lambda: base_config(network=network_block(timeout_ms=0)),
    ),
    Case(
        "invalid_network_unknown_key",
        False,
        # Unknown key inside network.
        lambda: base_config(network=network_block(probe_timeout=5)),
    ),
    Case(
        "invalid_payload_prefix_number",
        False,
        # Strict scalar types: a numeric payload prefix is rejected even though
        # yaml-cpp would stringify it (from the former root-level
        # test_config_bad.yaml fixture).
        lambda: base_config(payload=payload_block(prefix=123, suffix="test")),
    ),
    Case(
        "invalid_payload_scalar",
        False,
        # payload must be a map or null.
        lambda: base_config(payload="GET /index.html"),
    ),
    Case(
        "invalid_payload_unknown_key",
        False,
        # Unknown key inside payload.
        lambda: base_config(payload={"middle": "injected"}),
    ),
    Case(
        "invalid_port_detection_primary",
        False,
        # port_detection.primary is a closed enum.
        lambda: base_config(port_detection=port_detection_block(primary="inotify")),
    ),
    Case(
        "invalid_port_detection_unknown_key",
        False,
        # Unknown key inside port_detection.
        lambda: base_config(port_detection=port_detection_block(primary="procfs", mode="procfs")),
    ),
    Case(
        "invalid_port_detection_verify_ownership_type",
        False,
        # port_detection.verify_ownership must be a boolean, not a string.
        lambda: base_config(port_detection=port_detection_block(primary="procfs", verify_ownership="true")),
    ),
    Case(
        "invalid_primary_ptrace",
        False,
        # ptrace port detection was removed: the primary enum is closed to procfs/seccomp.
        lambda: base_config(port_detection=port_detection_block(primary="ptrace")),
    ),
    Case(
        "invalid_root_not_map",
        False,
        # Root node must be a map.
        lambda: ["just", "a", "list"],
    ),
    Case(
        "invalid_single_underscore_key",
        False,
        # Only root keys with a double-underscore prefix are ignored helpers;
        # a single underscore is an unknown root key and must be rejected.
        lambda: {
            "_helper": {"port": 8080},
            "target": target_block(binary="/usr/sbin/nginx"),
            "network": network_block(),
        },
    ),
    Case(
        "invalid_target_args_empty",
        False,
        # An empty args list is rejected by the loader (config.cpp): omit `args`
        # instead.
        lambda: base_config(target=target_block(args=[])),
    ),
    Case(
        "invalid_target_args_scalar",
        False,
        # args must be a list of strings.
        lambda: base_config(target=target_block(args="not-a-list")),
    ),
    Case(
        "invalid_target_env_preserve",
        False,
        # env_preserve is a closed enum.
        lambda: base_config(target=target_block(env_preserve="sometimes")),
    ),
    Case(
        "invalid_target_env_value_type",
        False,
        # env values must be strings.
        lambda: base_config(target=target_block(env={"FOO": 5})),
    ),
    Case(
        "invalid_target_missing_binary",
        False,
        # target.binary is required.
        lambda: {"target": {"args": ["./target"]}, "network": network_block()},
    ),
    Case(
        "invalid_unknown_root_key",
        False,
        # Unknown key at the root level.
        lambda: {**base_config(), "bogus_section": {}},
    ),
]
