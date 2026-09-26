##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## shared helpers for the test suite
##

import contextlib
import io
import os
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def capture_output(func, *args, **kwargs):
    """Run func and capture everything written to stdout and stderr.

    Returns (return_code, raw_stdout_bytes, stderr_string). Captures both
    print() (text) and sys.stdout.buffer.write() (bytes), which the decipher
    paths use, plus the error messages the error paths print on stderr.
    """

    buffer = io.BytesIO()
    wrapper = io.TextIOWrapper(buffer, encoding="utf-8")
    err = io.StringIO()

    with contextlib.redirect_stdout(wrapper), contextlib.redirect_stderr(err):
        result = func(*args, **kwargs)
        wrapper.flush()

    return result, buffer.getvalue(), err.getvalue()
