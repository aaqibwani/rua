"""CLI tests.

The Dockerfile's CMD and both Compose services invoke this console script. If the
argument surface drifts, the container starts and immediately dies, so the exact
flags the Dockerfile passes are asserted here.
"""

from __future__ import annotations

import pytest

from rua import __version__
from rua.cli import _build_parser, main


def test_serve_accepts_the_flags_the_dockerfile_passes() -> None:
    # Dockerfile: CMD ["rua", "serve", "--host", "0.0.0.0", "--port", "8080"]
    args = _build_parser().parse_args(["serve", "--host", "0.0.0.0", "--port", "8080"])
    assert args.command == "serve"
    assert args.host == "0.0.0.0"
    assert args.port == 8080
    assert args.reload is False


def test_serve_defaults_to_loopback() -> None:
    # Binding 0.0.0.0 must be an explicit choice, not the default for a local run.
    args = _build_parser().parse_args(["serve"])
    assert args.host == "127.0.0.1"
    assert args.port == 8080


def test_serve_reload_flag() -> None:
    assert _build_parser().parse_args(["serve", "--reload"]).reload is True


def test_scheduler_subcommand_exists() -> None:
    # docker-compose.yml: command: rua scheduler
    assert _build_parser().parse_args(["scheduler"]).command == "scheduler"


def test_no_command_is_an_error() -> None:
    with pytest.raises(SystemExit) as exc:
        _build_parser().parse_args([])
    assert exc.value.code == 2


def test_unknown_command_is_an_error() -> None:
    with pytest.raises(SystemExit) as exc:
        _build_parser().parse_args(["migrate"])
    assert exc.value.code == 2


def test_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out
