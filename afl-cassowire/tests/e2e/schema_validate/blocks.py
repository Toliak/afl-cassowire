"""Reusable *valid* config blocks for building schema-validation fixtures.

Each builder returns a fresh dict, so cases never share state by accident
(intentional sharing inside a single config is how YAML anchors/aliases are
exercised - see cases.py). Values that override a block key must stay valid;
only cases.py knows which mutations are expected to be rejected.
"""

from typing import Any


def target_block(**overrides: Any) -> dict[str, Any]:
    """Minimal valid `target:` section (binary is the only required key)."""
    return {"binary": "./target", **overrides}


def network_block(**overrides: Any) -> dict[str, Any]:
    """Minimal valid `network:` section (port is the only required key)."""
    return {"port": 8080, **overrides}


def afl_block(**overrides: Any) -> dict[str, Any]:
    """Valid `afl:` section (all keys optional)."""
    return {"loop_count": 1000, **overrides}


def port_detection_block(**overrides: Any) -> dict[str, Any]:
    """Valid `port_detection:` section (all keys optional)."""
    return {"primary": "procfs", **overrides}


def cleanup_block(**overrides: Any) -> dict[str, Any]:
    """Valid `cleanup:` section (all keys optional)."""
    return {"enabled": True, "on_port_conflict": "error", **overrides}


def payload_block(**overrides: Any) -> dict[str, Any]:
    """Valid `payload:` section (all keys optional; values str or bytes)."""
    return dict(overrides)


def sequence_block(**overrides: Any) -> dict[str, Any]:
    """Valid `sequence:` section (only `delimiter` is required when enabled)."""
    block: dict[str, Any] = {
        "enabled": True,
        "delimiter": b"\r\n\r\n",
        "keep_delimiter": True,
        "response_poll_us": 100,
        "initial_poll_us": 0,
        "final_poll_us": 100,
        "max_messages": 64,
    }
    block.update(overrides)
    return block


def base_config(**sections: Any) -> dict[str, Any]:
    """Base valid config: only the required sections, plus any extra sections."""
    return {"target": target_block(), "network": network_block(), **sections}
