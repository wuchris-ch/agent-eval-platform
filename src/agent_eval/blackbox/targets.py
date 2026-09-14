"""Bounded, blind transports. Targets see inputs, never cases or scoring policy."""

from __future__ import annotations

import contextlib
import http.client
import math
import os
import re
import selectors
import signal
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import JsonValue

from .models import MAX_PAYLOAD_BYTES, ErrorCode, digest, json_bytes, parse_json

# Explicit extra names may be supplied for any vendor or locally installed agent.
BASE_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_STDERR_BYTES = 64 * 1024


class TargetError(RuntimeError):
    def __init__(self, code: ErrorCode):
        self.code = code
        super().__init__(code)


class TargetCancelled(RuntimeError):
    """Owned process stopped; external side effects can still be unknown."""


class Target(Protocol):
    mode: Literal["command", "http"]
    identity: str

    def invoke(self, input_value: JsonValue) -> JsonValue: ...


def _timeout(value: float) -> float:
    if not math.isfinite(value) or value <= 0:
        raise ValueError("timeout must be a finite positive number")
    return value


@dataclass(frozen=True)
class ResponseDecoder:
    format: Literal["text", "json"] = "text"
    pointer: str | None = None

    def __post_init__(self):
        if self.format not in {"text", "json"}:
            raise ValueError("response format must be text or json")
        if self.pointer is not None:
            if self.format != "json":
                raise ValueError("a response pointer requires JSON output")
            if self.pointer and not self.pointer.startswith("/"):
                raise ValueError("response pointer must be empty or start with /")
            if re.search(r"~(?![01])", self.pointer):
                raise ValueError("invalid JSON pointer escape")

    def decode(self, raw: bytes) -> JsonValue:
        try:
            if len(raw) > MAX_PAYLOAD_BYTES:
                raise TargetError("target_output_limit")
            if self.format == "text":
                return raw.decode("utf-8")
            value = parse_json(raw)
            if self.pointer:
                for part in self.pointer[1:].split("/"):
                    key = part.replace("~1", "/").replace("~0", "~")
                    if isinstance(value, list):
                        if not re.fullmatch(r"0|[1-9][0-9]*", key):
                            raise ValueError("invalid array index")
                        value = value[int(key)]
                    elif isinstance(value, dict):
                        value = value[key]
                    else:
                        raise ValueError("pointer traverses a scalar")
            # Validate recursively and reject JSON's overflow-to-infinity case.
            json_bytes(value)
            return value
        except (
            ValueError,
            UnicodeError,
            KeyError,
            IndexError,
            TypeError,
            RecursionError,
        ):
            raise TargetError("invalid_output") from None


def _stop(process: subprocess.Popen) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def _drain(process: subprocess.Popen, deadline: float, cancel_check=None) -> bytes:
    streams = ((process.stdout, MAX_PAYLOAD_BYTES), (process.stderr, MAX_STDERR_BYTES))
    output = bytearray()
    counts = {}
    with selectors.DefaultSelector() as selector:
        for stream, limit in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, limit)
            counts[stream] = 0
        while selector.get_map():
            if cancel_check is not None and cancel_check():
                raise TargetCancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TargetError("target_timeout")
            for key, _ in selector.select(min(remaining, 0.1)):
                data = os.read(key.fileobj.fileno(), 64 * 1024)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                counts[key.fileobj] += len(data)
                if counts[key.fileobj] > key.data:
                    raise TargetError("target_output_limit")
                if key.fileobj is process.stdout:
                    output.extend(data)
        # EOF can precede process exit. Wait within the original deadline.
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise TargetError("target_timeout") from None
    if process.returncode:
        raise TargetError("target_exit")
    return bytes(output)


class CommandTarget:
    mode = "command"

    def __init__(
        self,
        command: list[str],
        *,
        timeout: float = 120,
        decoder: ResponseDecoder = ResponseDecoder(),
        env_names: list[str] | None = None,
    ):
        if not command or any(not arg or "\x00" in arg for arg in command):
            raise ValueError("command must contain nonempty argv entries")
        self.cancel_check = None
        self.command = list(command)
        self.timeout = _timeout(timeout)
        self.decoder = decoder
        names = sorted(set(env_names or []))
        if any(
            not ENV_NAME.fullmatch(name) or name not in os.environ for name in names
        ):
            raise ValueError("pass-env must name an existing environment variable")
        self.environment = {
            name: os.environ[name] for name in (*BASE_ENV, *names) if name in os.environ
        }
        self.identity = digest(
            {
                "mode": self.mode,
                "argv": command,
                "env_names": names,
                "timeout": timeout,
                "format": decoder.format,
                "pointer": decoder.pointer,
            }
        )

    def invoke(self, input_value: JsonValue) -> JsonValue:
        # Strings are sent unchanged. Objects/arrays use canonical JSON.
        payload = (
            input_value.encode("utf-8")
            if isinstance(input_value, str)
            else json_bytes(input_value)
        )
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise TargetError("target_output_limit")
        # A clean working directory prevents incidental discovery of suite files.
        # This is not an OS sandbox; use a container/service for untrusted code.
        with tempfile.TemporaryDirectory(prefix="agent-eval-target-") as cwd:
            with tempfile.TemporaryFile() as stdin:
                stdin.write(payload)
                stdin.seek(0)
                try:
                    process = subprocess.Popen(
                        self.command,
                        stdin=stdin,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=cwd,
                        env=self.environment,
                        start_new_session=True,
                    )
                except (OSError, ValueError):
                    raise TargetError("target_start") from None
                try:
                    raw = _drain(
                        process, time.monotonic() + self.timeout, self.cancel_check
                    )
                finally:
                    _stop(process)
                    process.stdout.close()
                    process.stderr.close()
        return self.decoder.decode(raw)


class HttpTarget:
    mode = "http"

    def __init__(
        self,
        endpoint: str,
        *,
        timeout: float = 120,
        decoder: ResponseDecoder = ResponseDecoder(),
        bearer_token: str | None = None,
    ):
        try:
            parts = urlsplit(endpoint)
            port = parts.port
        except ValueError:
            raise ValueError("invalid target endpoint") from None
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.fragment
            or any(ord(char) < 33 for char in endpoint)
        ):
            raise ValueError(
                "target endpoint must be an HTTP(S) URL without credentials or fragment"
            )
        if bearer_token is not None and (
            not bearer_token or "\r" in bearer_token or "\n" in bearer_token
        ):
            raise ValueError("invalid bearer token")
        self.parts, self.port = parts, port
        self.timeout = _timeout(timeout)
        self.decoder = decoder
        self.bearer_token = bearer_token
        self.identity = digest(
            {
                "mode": self.mode,
                "endpoint": endpoint,
                "timeout": timeout,
                "format": decoder.format,
                "pointer": decoder.pointer,
            }
        )

    def invoke(self, input_value: JsonValue) -> JsonValue:
        payload = json_bytes(input_value)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain",
        }
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        connection_type = (
            http.client.HTTPSConnection
            if self.parts.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_type(
            self.parts.hostname, self.port, timeout=self.timeout
        )
        path = self.parts.path or "/"
        if self.parts.query:
            path += "?" + self.parts.query
        deadline = time.monotonic() + self.timeout
        expired = threading.Event()
        sock = None

        def interrupt_socket():
            expired.set()
            active = sock or connection.sock
            if active is not None:
                with contextlib.suppress(OSError):
                    active.shutdown(socket.SHUT_RDWR)

        # Socket timeouts alone reset on each incoming byte. A watchdog also
        # bounds servers that continually drip response headers or body bytes.
        timer = threading.Timer(self.timeout, interrupt_socket)
        timer.daemon = True
        timer.start()
        try:
            connection.connect()
            sock = connection.sock
            if expired.is_set():
                raise TargetError("target_timeout")
            connection.request("POST", path, body=payload, headers=headers)
            if sock:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
            with connection.getresponse() as response:
                if not 200 <= response.status < 300:
                    # Never follow redirects with authentication or test inputs.
                    raise TargetError("target_transport")
                raw = bytearray()
                while not response.isclosed():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TargetError("target_timeout")
                    # HTTPResponse may own the socket after Connection: close.
                    if sock:
                        sock.settimeout(remaining)
                    chunk = response.read1(
                        min(64 * 1024, MAX_PAYLOAD_BYTES + 1 - len(raw))
                    )
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > MAX_PAYLOAD_BYTES:
                        raise TargetError("target_output_limit")
        except TimeoutError:
            raise TargetError("target_timeout") from None
        except (OSError, ValueError, http.client.HTTPException):
            raise TargetError(
                "target_timeout" if expired.is_set() else "target_transport"
            ) from None
        finally:
            timer.cancel()
            connection.close()
        if expired.is_set():
            raise TargetError("target_timeout")
        return self.decoder.decode(bytes(raw))
