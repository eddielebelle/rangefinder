"""The review-then-save prompt (`capture` with no -o at an interactive terminal shows the twin, then
offers to save it). The prompt itself is TTY-gated in cmd_capture; here we test the save helper."""

import builtins
from unittest import mock

from rangefinder.cli import _prompt_save


def test_prompt_save_blank_declines(tmp_path):
    with mock.patch.object(builtins, "input", lambda: "   "):
        assert _prompt_save('{"x":1}\n') is None            # blank -> not saved
    assert list(tmp_path.iterdir()) == []                    # nothing written


def test_prompt_save_writes_to_given_path(tmp_path):
    dest = tmp_path / "twin.json"
    with mock.patch.object(builtins, "input", lambda: str(dest)):
        result = _prompt_save('{"x":1}\n')
    assert result == dest
    assert dest.read_text() == '{"x":1}\n'                   # exactly what was shown on stdout


def test_prompt_save_eof_declines_gracefully():
    def _eof():
        raise EOFError
    with mock.patch.object(builtins, "input", _eof):
        assert _prompt_save("{}\n") is None                  # ^D / no input -> not saved, no crash
