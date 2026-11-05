"""Experimental, opt-in decimal-preserving ChatGPT *index projection* codec.

This is NOT wired into ``ChatGPTArchive`` or its V1 database/AES-GCM format.
The authenticated original ZIP is the only byte-lossless source.  V2 preserves
JSON decimal coefficients and scales (rather than rounding through binary64),
but JSON token spellings such as ``1e0`` versus ``1e+00`` are *not* preserved.

Consumers must explicitly recognize the format marker.  No migration, model
authority, historical-memory admission or public storage is implemented here.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import io
import json


CODEC_ID = "STM_CHATGPT_DECIMAL_PROJECTION_V2_CANDIDATE"
_MAGIC = b"STM_CGPT_DECIMAL_V2\x00"
MAX_V2_RECORD_BYTES = 128 * 1024 * 1024
MAX_V2_NODES = 200_000
MAX_V2_DEPTH = 128


class DecimalCodecFailure(ValueError):
    """An unsupported or ambiguously represented JSON record was rejected."""


def _reject_constant(_: str) -> None:
    raise DecimalCodecFailure("nonfinite JSON numeric constant is not allowed")


def _distinct_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            # V1's last-wins behavior is intentionally NOT copied into this
            # separately versioned candidate representation.
            raise DecimalCodecFailure("ambiguous duplicate JSON object key")
        result[key] = value
    return result


def parse_decimal_record_v2(source: str | bytes) -> dict[str, object]:
    """Parse a single bounded source JSON object without binary-float rounding.

    This accepts no ZIP path or archive handle. It does not perform source
    attribution, authenticate a caller or establish full-export coverage.
    """
    if type(source) not in (str, bytes):
        raise DecimalCodecFailure("JSON source must be text or UTF-8 bytes")
    if len(source) > MAX_V2_RECORD_BYTES:
        raise DecimalCodecFailure("record input exceeds codec budget")
    try:
        if type(source) is bytes:
            # json.loads(bytes) otherwise accepts UTF-16/32 by auto-detection,
            # contradicting the canonical UTF-8-only source contract.
            source = source.decode("utf-8", "strict")
        value = json.loads(
            source, parse_float=Decimal, parse_int=int,
            parse_constant=_reject_constant, object_pairs_hook=_distinct_object,
        )
    except DecimalCodecFailure:
        raise
    except (ValueError, UnicodeError, RecursionError, TypeError, InvalidOperation):
        raise DecimalCodecFailure("unsupported source JSON") from None
    if type(value) is not dict:
        raise DecimalCodecFailure("top-level conversation must be an object")
    return value


def encode_decimal_record_v2(record: dict[str, object]) -> bytes:
    """Return a version-marked canonical projection, never V1 JSON bytes.

    Only values parsed with decimal precision should be passed: Python floats
    are categorically refused. This is bounded and deterministic, not a claim
    that original number lexemes or whitespace can be reconstructed.
    """
    if type(record) is not dict:
        raise DecimalCodecFailure("conversation record must be an object")
    sink = io.BytesIO()
    sink.write(_MAGIC)
    nodes = 0

    def emit(chunk: str) -> None:
        data = chunk.encode("utf-8", "strict")
        if sink.tell() + len(data) > MAX_V2_RECORD_BYTES:
            raise DecimalCodecFailure("record exceeds codec budget")
        sink.write(data)

    def emit_json_string(value: str) -> None:
        # json.dumps() on a single source-controlled 128-MB string could
        # transiently allocate hundreds of megabytes for escaped Unicode.
        # Slice the source string before quoting to keep each intermediate
        # escaped chunk bounded; slices have no JSON delimiter semantics.
        emit('"')
        for start in range(0, len(value), 4096):
            emit(json.dumps(value[start:start + 4096], ensure_ascii=True)[1:-1])
        emit('"')

    def walk(value: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_V2_NODES or depth > MAX_V2_DEPTH:
            raise DecimalCodecFailure("JSON structure exceeds codec budget")
        if value is None:
            emit("null")
        elif type(value) is bool:
            emit("true" if value else "false")
        elif type(value) is str:
            emit_json_string(value)
        elif type(value) is int:
            emit(str(value))
        elif type(value) is Decimal:
            if not value.is_finite():
                raise DecimalCodecFailure("nonfinite decimal rejected")
            # Decimal's default scientific notation does not expand a huge
            # exponent into unbounded fixed-point zeroes.
            emit(str(value))
        elif type(value) is float:
            raise DecimalCodecFailure("binary floating-point input rejected")
        elif type(value) is list:
            emit("[")
            for index, part in enumerate(value):
                if index:
                    emit(",")
                walk(part, depth + 1)
            emit("]")
        elif type(value) is dict:
            if any(type(key) is not str for key in value):
                raise DecimalCodecFailure("JSON object keys must be strings")
            emit("{")
            for index, key in enumerate(sorted(value)):
                if index:
                    emit(",")
                emit_json_string(key)
                emit(":")
                walk(value[key], depth + 1)
            emit("}")
        else:
            raise DecimalCodecFailure("unsupported JSON value type")

    try:
        walk(record, 0)
    except DecimalCodecFailure:
        raise
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecimalCodecFailure("record encoding failed") from None
    return sink.getvalue()


def decode_decimal_record_v2(blob: bytes) -> dict[str, object]:
    """Read only canonical V2 projection bytes; legacy V1 fails closed."""
    if type(blob) is not bytes or not blob.startswith(_MAGIC):
        raise DecimalCodecFailure("version marker required")
    if len(blob) > MAX_V2_RECORD_BYTES:
        raise DecimalCodecFailure("record exceeds codec budget")
    record = parse_decimal_record_v2(blob[len(_MAGIC):])
    if encode_decimal_record_v2(record) != blob:
        raise DecimalCodecFailure("noncanonical V2 projection")
    return record
