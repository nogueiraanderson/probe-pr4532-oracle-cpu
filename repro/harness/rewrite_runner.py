"""Run the PR's cpu_cves.py unchanged, with https://www.oracle.com rewired to the mock.

Usage:
  python3 -B rewrite_runner.py --pr PR_DIR --log LOG_JSONL --mock http://127.0.0.1:PORT
                               [--no-rewrite] -- <cpu_cves.py arguments>

Harness-only monkeypatches, the PR files are never edited:
  * urllib.request.OpenerDirector.open logs every ORIGINAL url (scheme, host,
    path) and, unless --no-rewrite, maps https://www.oracle.com/... to the mock.
    Any other host or scheme passes through untouched and is logged as such.
  * http.client request/response hooks count the bytes the PR actually read.
The log is JSON lines, flushed per event, so a killed run still leaves evidence.
The final line carries the exit code and ru_maxrss.
"""

from __future__ import annotations

import atexit
import http.client
import json
import resource
import runpy
import socket
import sys
import time
import urllib.parse
import urllib.request

ORACLE_PREFIX = "https://www.oracle.com/"


def _parse_args(argv: list[str]) -> tuple[dict[str, str], list[str]]:
    opts: dict[str, str] = {"rewrite": "1"}
    rest: list[str] = []
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag == "--":
            rest = argv[index + 1 :]
            break
        if flag == "--no-rewrite":
            opts["rewrite"] = "0"
            index += 1
            continue
        opts[flag.lstrip("-")] = argv[index + 1]
        index += 2
    return opts, rest


OPTS, CPU_ARGS = _parse_args(sys.argv[1:])
PR_DIR = OPTS["pr"]
LOG_PATH = OPTS["log"]
MOCK_BASE = OPTS.get("mock", "").rstrip("/")
REWRITE = OPTS["rewrite"] == "1" and bool(MOCK_BASE)
T0 = time.monotonic()
LOG_FH = open(LOG_PATH, "a", encoding="utf-8")


def emit(event: dict) -> None:
    event["t"] = round(time.monotonic() - T0, 3)
    LOG_FH.write(json.dumps(event) + "\n")
    LOG_FH.flush()


_orig_open = urllib.request.OpenerDirector.open


def _logging_open(self, fullurl, data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
    request = fullurl if isinstance(fullurl, urllib.request.Request) else urllib.request.Request(fullurl)
    original = request.full_url
    parsed = urllib.parse.urlsplit(original)
    rewritten = False
    if REWRITE and original.startswith(ORACLE_PREFIX):
        request.full_url = MOCK_BASE + "/" + original[len(ORACLE_PREFIX) :]
        rewritten = True
    emit(
        {
            "ev": "open",
            "original": original,
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "path": parsed.path,
            "rewritten": rewritten,
            "target": request.full_url,
            "timeout": None if timeout is socket._GLOBAL_DEFAULT_TIMEOUT else timeout,
        }
    )
    return _orig_open(self, request, data, timeout)


urllib.request.OpenerDirector.open = _logging_open

_orig_putrequest = http.client.HTTPConnection.putrequest
_orig_getresponse = http.client.HTTPConnection.getresponse


def _putrequest(self, method, url, *args, **kwargs):
    scheme = "https" if isinstance(self, http.client.HTTPSConnection) else "http"
    self._harness_entry = {"ev": "http", "url": f"{scheme}://{self.host}:{self.port}{url}", "status": None, "bytes": 0}
    return _orig_putrequest(self, method, url, *args, **kwargs)


def _getresponse(self):
    entry = getattr(self, "_harness_entry", None)
    response = _orig_getresponse(self)
    if entry is not None:
        entry["status"] = response.status
        entry["location"] = response.getheader("Location")
        emit(dict(entry))
        original_read = response.read

        def counting_read(amt=None):
            data = original_read(amt)
            entry["bytes"] += len(data)
            if not data or amt is None:
                emit({"ev": "http_done", "url": entry["url"], "bytes": entry["bytes"]})
            return data

        response.read = counting_read
    return response


http.client.HTTPConnection.putrequest = _putrequest
http.client.HTTPConnection.getresponse = _getresponse

EXIT_CODE = {"code": 0}


def _finish() -> None:
    emit(
        {
            "ev": "exit",
            "code": EXIT_CODE["code"],
            "maxrss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "rewrite": REWRITE,
        }
    )
    LOG_FH.close()


atexit.register(_finish)
emit({"ev": "start", "pr": PR_DIR, "mock": MOCK_BASE, "rewrite": REWRITE, "args": CPU_ARGS})
sys.dont_write_bytecode = True
sys.path.insert(0, PR_DIR)
sys.argv = [PR_DIR + "/cpu_cves.py"] + CPU_ARGS
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
except SystemExit as exc:
    code = exc.code
    EXIT_CODE["code"] = code if isinstance(code, int) else (0 if code is None else 1)
    raise
except BaseException:
    EXIT_CODE["code"] = 70
    raise
