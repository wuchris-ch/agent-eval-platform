import io
import json
import sys
import time
from datetime import UTC, datetime, timedelta

import pytest

import agent_eval.credentials as credentials_module
from agent_eval.credentials import (
    CredentialMaterial,
    CredentialRedactor,
    load_trial_credentials,
)


def test_adapter_credentials_are_scoped(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-test-key")
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    auth = tmp_path / ".codex" / "auth.json"
    auth.parent.mkdir()
    auth.write_text('{"tokens": "codex-test-token"}')

    claude = load_trial_credentials("claude-code")
    codex = load_trial_credentials("codex")

    assert claude.env_keys == ("ANTHROPIC_API_KEY",)
    assert "codex-auth" not in claude.values
    assert codex.env_keys == ()
    assert codex.file_items == {"codex-auth": "codex-auth.json"}
    assert "ANTHROPIC_API_KEY" not in codex.values


def test_broker_material_is_short_lived_and_never_uses_shell(monkeypatch, tmp_path):
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    broker = tmp_path / "broker.py"
    broker.write_text(
        "import json\n"
        f"print(json.dumps({{'env': {{'TOKEN': 'value'}}, 'expires_at': {expires!r}}}))\n"
    )
    monkeypatch.setenv(
        "AGENT_EVAL_CREDENTIAL_COMMAND",
        f"{sys.executable} {broker} --literal-semicolon ';'",
    )

    material = load_trial_credentials("custom")

    assert material.values == {"TOKEN": "value"}
    assert material.mode == "short-lived"
    assert material.source == "credential-broker"


def test_broker_expiry_must_cover_trial_and_long_ttl_is_not_short_lived(
    monkeypatch, tmp_path
):
    broker = tmp_path / "broker.py"
    expires = (datetime.now(UTC) + timedelta(minutes=2)).isoformat()
    broker.write_text(
        "import json\n"
        f"print(json.dumps({{'env': {{'TOKEN': 'value'}}, 'expires_at': {expires!r}}}))\n"
    )
    monkeypatch.setenv("AGENT_EVAL_CREDENTIAL_COMMAND", f"{sys.executable} {broker}")

    with pytest.raises(ValueError, match="trial timeout"):
        load_trial_credentials("custom", minimum_ttl_seconds=300)

    far_expiry = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    broker.write_text(
        "import json\n"
        f"print(json.dumps({{'env': {{'TOKEN': 'value'}}, 'expires_at': {far_expiry!r}}}))\n"
    )
    material = load_trial_credentials("custom", minimum_ttl_seconds=300)
    assert material.mode == "expiring-broker-credential"


def test_broker_failure_does_not_echo_secret_output(monkeypatch, tmp_path):
    broker = tmp_path / "bad.py"
    broker.write_text("import sys\nprint('VERY_SECRET')\nsys.exit(4)\n")
    monkeypatch.setenv("AGENT_EVAL_CREDENTIAL_COMMAND", f"{sys.executable} {broker}")

    with pytest.raises(RuntimeError) as caught:
        load_trial_credentials("custom")

    assert "VERY_SECRET" not in str(caught.value)


@pytest.mark.parametrize(
    "material",
    [
        lambda: CredentialMaterial(values={}),
        lambda: CredentialMaterial(values={"x": "y"}, env_keys=("BAD-NAME",)),
        lambda: CredentialMaterial(values={"x": "y"}, file_items={"x": "../auth.json"}),
    ],
)
def test_invalid_material_is_rejected(material):
    with pytest.raises(ValueError):
        material()


def test_broker_rejects_unknown_fields_without_exposing_values(monkeypatch, tmp_path):
    broker = tmp_path / "bad-schema.py"
    broker.write_text(
        "import json\n"
        "print(json.dumps({'env': {'TOKEN': 'VERY_SECRET'}, 'unexpected': True}))\n"
    )
    monkeypatch.setenv("AGENT_EVAL_CREDENTIAL_COMMAND", f"{sys.executable} {broker}")

    with pytest.raises(ValueError) as caught:
        load_trial_credentials("custom")

    assert "unsupported fields" in str(caught.value)
    assert "VERY_SECRET" not in str(caught.value)


def test_exact_redactor_covers_api_keys_and_json_auth_representations():
    api_key = "sk-enterprise-agent-eval-api-key"
    access_token = "access-token-from-codex-auth-json"
    refresh_token = 'refresh-token-with-"quotes"-and-\\slashes'
    auth = '{"tokens":{"access_token":%s,"refresh_token":%s},"mode":"chatgpt"}' % (
        credentials_module.json.dumps(access_token),
        credentials_module.json.dumps(refresh_token),
    )
    material = CredentialMaterial(
        values={"API_KEY": api_key, "codex-auth": auth},
        env_keys=("API_KEY",),
        file_items={"codex-auth": "codex-auth.json"},
    )
    redactor = CredentialRedactor.from_material(material)
    serialized_auth = credentials_module.json.dumps(auth)
    payload = (
        f"api={api_key}\naccess={access_token}\nrefresh={refresh_token}\n"
        f"auth={auth}\nserialized={serialized_auth}\nmode=chatgpt\n"
    ).encode()

    redacted = redactor.redact_bytes(payload)

    for secret in (api_key, access_token, refresh_token, auth, serialized_auth):
        assert secret.encode() not in redacted
    assert redactor.placeholder in redacted
    assert b"mode=chatgpt" not in redacted


def test_stream_search_detects_a_token_across_read_boundaries():
    secret = "credential-spanning-stream-chunks"
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": secret}, env_keys=("TOKEN",))
    )
    stream = io.BytesIO(b"prefix-12345" + secret.encode() + b"-suffix")

    assert redactor.contains_stream(
        stream,
        maximum_bytes=1024,
        chunk_bytes=7,
    )


@pytest.mark.parametrize(
    "encoded",
    [
        b"opaque\\/credential\\/value",
        b"\\u006f\\u0070\\u0061\\u0071\\u0075\\u0065/credential/value",
        b"o\\u0070aque/cred\\u0065ntial/val\\u0075e",
    ],
)
def test_alternate_valid_json_escapes_fail_closed(encoded):
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(
            values={"TOKEN": "opaque/credential/value"},
            env_keys=("TOKEN",),
        )
    )

    assert redactor.contains_bytes(encoded)
    with pytest.raises(
        credentials_module.CredentialRedactionError,
        match="could not be safely redacted",
    ):
        redactor.redact_bytes(b"copied=" + encoded)


def test_stream_search_detects_unicode_escaped_token_across_boundaries():
    secret = "credential-stream"
    encoded = "".join(f"\\u{ord(character):04x}" for character in secret).encode()
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": secret}, env_keys=("TOKEN",))
    )

    assert redactor.contains_stream(
        io.BytesIO(b"prefix=" + encoded + b";suffix"),
        maximum_bytes=4096,
        chunk_bytes=11,
    )


def test_stream_read_window_covers_largest_direct_pattern():
    class RecordingStream(io.BytesIO):
        requested_sizes: list[int]

        def __init__(self, value: bytes):
            super().__init__(value)
            self.requested_sizes = []

        def read(self, size=-1):
            self.requested_sizes.append(size)
            return super().read(size)

    secret = "s" * (credentials_module.REDACTION_READ_CHUNK_BYTES + 1)
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": secret}, env_keys=("TOKEN",))
    )
    stream = RecordingStream(b"x")

    assert not redactor.contains_stream(stream, maximum_bytes=1)
    assert stream.requested_sizes[0] >= redactor.maximum_pattern_bytes


def test_streaming_json_unescaper_matches_whole_buffer_decoder():
    samples = [
        b"plain text",
        b"trailing\\",
        b'simple=\\n slash=\\/ quote=\\"',
        b"unicode=\\u0061 invalid=\\u00zz",
        b"incomplete=\\u0\\n shorter=\\u\\t",
        b"pair=\\ud83d\\ude00 lone=\\ud83d!",
    ]

    for sample in samples:
        expected, expected_changed = credentials_module._json_unescape_bytes_once(
            sample
        )
        for split in range(len(sample) + 1):
            decoder = credentials_module._StreamingJSONUnescaper()
            output = decoder.feed(sample[:split])
            output += decoder.feed(sample[split:])
            output += decoder.finish()

            assert output == expected
            assert decoder.changed is expected_changed
        for chunk_bytes in range(1, 14):
            decoder = credentials_module._StreamingJSONUnescaper()
            output = b"".join(
                decoder.feed(sample[offset : offset + chunk_bytes])
                for offset in range(0, len(sample), chunk_bytes)
            )
            output += decoder.finish()

            assert output == expected
            assert decoder.changed is expected_changed


def _nest_json_escape(value: bytes, rounds: int) -> bytes:
    nested = value.decode()
    for _ in range(rounds):
        nested = json.dumps(nested)[1:-1]
    return nested.encode()


@pytest.mark.parametrize(
    "decode_layers",
    range(credentials_module.MAX_JSON_ESCAPE_DECODE_ROUNDS + 1),
)
def test_stream_search_detects_credentials_at_every_json_layer(decode_layers):
    secret = "credential-at-every-layer"
    if decode_layers == 0:
        nested = secret.encode()
    else:
        encoded_secret = b"".join(f"\\u{byte:04x}".encode() for byte in secret.encode())
        nested = _nest_json_escape(encoded_secret, decode_layers - 1)
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": secret}, env_keys=("TOKEN",))
    )

    assert redactor.contains_stream(
        io.BytesIO(b"prefix=" + nested + b";suffix"),
        maximum_bytes=len(nested) + 14,
        chunk_bytes=7,
    )


def test_nested_json_escape_layers_are_inspected_within_limit():
    secret = b"credential-value"
    encoded_secret = b"".join(f"\\u{byte:04x}".encode() for byte in secret)
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": secret.decode()}, env_keys=("TOKEN",))
    )

    assert redactor.contains_bytes(
        _nest_json_escape(
            encoded_secret,
            credentials_module.MAX_JSON_ESCAPE_DECODE_ROUNDS - 1,
        )
    )


def test_nested_json_escape_layers_are_inspected_across_stream_chunks():
    secret = "a" * 512
    encoded_secret = b"\\u0061" * len(secret)
    nested = _nest_json_escape(
        encoded_secret,
        credentials_module.MAX_JSON_ESCAPE_DECODE_ROUNDS - 1,
    )
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": secret}, env_keys=("TOKEN",))
    )

    assert len(nested) > credentials_module.REDACTION_READ_CHUNK_BYTES
    assert redactor.contains_stream(
        io.BytesIO(b"prefix=" + nested + b";suffix"),
        maximum_bytes=len(nested) + 14,
    )


def test_nested_json_escape_layers_fail_closed_beyond_limit():
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": "different-secret"}, env_keys=("TOKEN",))
    )

    too_deep = _nest_json_escape(
        b"\\u0061",
        credentials_module.MAX_JSON_ESCAPE_DECODE_ROUNDS,
    )

    with pytest.raises(
        credentials_module.CredentialRedactionError,
        match="JSON escape inspection limit",
    ):
        redactor.contains_bytes(too_deep)
    with pytest.raises(
        credentials_module.CredentialRedactionError,
        match="JSON escape inspection limit",
    ):
        redactor.contains_stream(
            io.BytesIO(too_deep),
            maximum_bytes=len(too_deep),
            chunk_bytes=7,
        )


@pytest.mark.parametrize("inner", [b"\\u00", b"\\u00zz", b"\\ud83d"])
def test_invalid_or_incomplete_escape_after_limit_does_not_false_positive(inner):
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(
            values={"TOKEN": "different-secret"},
            env_keys=("TOKEN",),
        )
    )
    nested = _nest_json_escape(
        inner,
        credentials_module.MAX_JSON_ESCAPE_DECODE_ROUNDS,
    )

    assert not redactor.contains_bytes(nested)
    assert not redactor.contains_stream(
        io.BytesIO(nested),
        maximum_bytes=len(nested),
        chunk_bytes=1,
    )


@pytest.mark.parametrize("auth", ["{}", '{"mode":"chatgpt"}'])
def test_projected_auth_file_is_redacted_even_without_known_secret_fields(auth):
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(
            values={"auth-file": auth},
            file_items={"auth-file": "auth.json"},
        )
    )

    assert auth.encode() not in redactor.redact_bytes(f"copied={auth}".encode())


def test_short_string_in_unfamiliar_auth_schema_is_credential_material():
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(
            values={"auth-file": '{"opaque":"s3cr3t9"}'},
            file_items={"auth-file": "auth.json"},
        )
    )

    assert redactor.contains_text("copied short token s3cr3t9")
    assert "s3cr3t9" not in redactor.redact_text("copied short token s3cr3t9")


def test_projected_json_rejects_duplicate_keys_without_exposing_values():
    first = "FIRST_CREDENTIAL_MUST_NOT_BE_DISCARDED"
    second = "SECOND_CREDENTIAL_MUST_NOT_BE_DISCARDED"
    material = CredentialMaterial(
        values={"auth-file": f'{{"token":"{first}","token":"{second}"}}'},
        file_items={"auth-file": "auth.json"},
    )

    with pytest.raises(
        credentials_module.CredentialRedactionError,
        match="duplicate object keys",
    ) as caught:
        CredentialRedactor.from_material(material)

    assert first not in str(caught.value)
    assert second not in str(caught.value)


def test_malformed_projected_json_fails_closed_without_exposing_values():
    secret = "PROJECTED_SECRET_123456"
    material = CredentialMaterial(
        values={"auth-file": f'{{"token":"{secret}"'},
        file_items={"auth-file": "auth.json"},
    )

    with pytest.raises(
        credentials_module.CredentialRedactionError,
        match="must contain strict JSON",
    ) as caught:
        CredentialRedactor.from_material(material)

    assert secret not in str(caught.value)


@pytest.mark.parametrize(
    ("auth", "copied"),
    [
        ('{"s3cr3t9":true}', "s3cr3t9"),
        ('{"pin":123456}', "123456"),
        ('{"pin":123.45}', "123.45"),
    ],
)
def test_projected_json_keys_and_number_spellings_are_credential_material(auth, copied):
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(
            values={"auth-file": auth},
            file_items={"auth-file": "auth.json"},
        )
    )

    assert redactor.contains_text(f"copied={copied}")
    assert copied not in redactor.redact_text(f"copied={copied}")


def test_projected_json_rejects_components_too_short_to_pattern_safely():
    for auth in ('{"x":"credential"}', '{"pin":1234}'):
        with pytest.raises(
            credentials_module.CredentialRedactionError,
            match="credential JSON",
        ):
            CredentialRedactor.from_material(
                CredentialMaterial(
                    values={"auth-file": auth},
                    file_items={"auth-file": "auth.json"},
                )
            )


def test_redaction_fails_closed_if_replacement_creates_another_secret():
    redactor = CredentialRedactor(
        patterns=(b"abcd", b"X"),
        placeholder=b"",
    )

    with pytest.raises(
        credentials_module.CredentialRedactionError,
        match="could not be safely redacted",
    ):
        redactor.redact_bytes(b"abXcd")


def test_credential_material_size_limits_are_generic_and_repr_hides_values():
    secret = "DO_NOT_EXPOSE_THIS_CREDENTIAL"
    material = CredentialMaterial(values={"TOKEN": secret}, env_keys=("TOKEN",))
    assert secret not in repr(material)

    oversized = secret + "x" * credentials_module.MAX_CREDENTIAL_VALUE_BYTES
    with pytest.raises(ValueError) as caught:
        CredentialMaterial(values={"TOKEN": oversized}, env_keys=("TOKEN",))

    assert secret not in str(caught.value)
    assert "size limit" in str(caught.value)


def test_broker_output_limit_fails_closed_without_echoing_output(monkeypatch, tmp_path):
    secret = "BROKER_OUTPUT_MUST_NEVER_REACH_AN_ERROR"
    broker = tmp_path / "oversized-broker.py"
    broker.write_text(
        f"import json\nprint(json.dumps({{'env': {{'TOKEN': {secret!r} * 100}}}}))\n"
    )
    monkeypatch.setattr(credentials_module, "MAX_BROKER_OUTPUT_BYTES", 128)
    monkeypatch.setenv("AGENT_EVAL_CREDENTIAL_COMMAND", f"{sys.executable} {broker}")

    with pytest.raises(RuntimeError) as caught:
        load_trial_credentials("custom")

    assert "safe size limit" in str(caught.value)
    assert secret not in str(caught.value)


def test_successful_broker_cannot_leave_a_descendant_running(monkeypatch, tmp_path):
    marker = tmp_path / "orphaned-child-ran"
    broker = tmp_path / "forking-broker.py"
    child = (
        "import pathlib,time; time.sleep(0.4); "
        f"pathlib.Path({str(marker)!r}).write_text('unsafe')"
    )
    broker.write_text(
        "import json,subprocess,sys\n"
        f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
        "print(json.dumps({'env': {'TOKEN': 'bounded-token'}}))\n"
    )
    monkeypatch.setenv(
        "AGENT_EVAL_CREDENTIAL_COMMAND",
        f"{sys.executable} {broker}",
    )

    material = load_trial_credentials("custom")
    time.sleep(0.6)

    assert material.values == {"TOKEN": "bounded-token"}
    assert not marker.exists()
