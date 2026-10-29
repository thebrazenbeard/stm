"""Opt-in token accounting at a specific local model/tokenizer/template boundary.

The core STM packer defaults to UTF-8 bytes. This module deliberately keeps
estimated bytes separate from verified backend-reported model token counts;
neither mode stores or claims inference-runtime KV-cache state.

An exact backend must count the *fully rendered* inference prompt with the same
tokenizer, chat template and special-token policy as the actual model runtime.
This library cannot independently certify the backend's correctness.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Literal, Protocol

from .context import BudgetOverflow, TokenBudget, Utf8ByteCounter
from .models import SessionKey


CountUnit = Literal["model_tokens", "utf8_bytes"]


def _valid_id(value: str) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 256 and not any(
        ord(char) < 32 or ord(char) == 127 for char in value
    )


@dataclass(frozen=True, slots=True)
class ModelTokenizerIdentity:
    """Identity that changes when model, tokenizer or rendered template changes."""

    model: str
    tokenizer: str
    template: str
    revision: str

    def __post_init__(self) -> None:
        for label in ("model", "tokenizer", "template", "revision"):
            if not _valid_id(getattr(self, label)):
                raise ValueError(f"{label} must be a nonempty identity (max 256 chars)")


class ExactTokenBackend(Protocol):
    """Engine-specific adapter for the exact *rendered prompt* token count.

    The embedding runtime must provide the matching identity and implement
    actual tokenization. A mock backend only establishes interface behavior.
    """

    def count_tokens(self, prompt: str, *, identity: ModelTokenizerIdentity) -> int: ...


@dataclass(frozen=True, slots=True)
class TokenMeasurement:
    quantity: int
    unit: CountUnit
    exact_backend: bool
    identity: ModelTokenizerIdentity
    session_cache_key: str


@dataclass(frozen=True, slots=True)
class BudgetAssessment:
    measurement: TokenMeasurement
    limit: int
    reserved: int
    guardband: int

    @property
    def available(self) -> int:
        return self.limit - self.reserved - self.guardband

    @property
    def fits(self) -> bool:
        return self.measurement.quantity <= self.available


class RuntimeTokenCounter:
    """ContextPacker-compatible counter for a *verified exact* backend only."""

    def __init__(self, identity: ModelTokenizerIdentity, backend: ExactTokenBackend) -> None:
        self.identity = identity
        self.backend = backend

    def count(self, text: str) -> int:
        if not isinstance(text, str):
            raise TypeError("rendered prompt must be text")
        value = self.backend.count_tokens(text, identity=self.identity)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("model token backend must return a nonnegative integer")
        return value


class TokenBudgetAdapter:
    """Checks prompt accounting without confusing bytes and model tokens.

    Without a backend, counts are UTF-8 bytes and can only be checked against a
    byte budget. With a backend, counts are model tokens and a caller can pass
    the exact counter into ``ContextPacker``. The caller must include system and
    chat templates in the passed text before interpreting the budget as total
    model-context occupancy.
    """

    def __init__(
        self,
        identity: ModelTokenizerIdentity,
        *,
        backend: ExactTokenBackend | None = None,
    ) -> None:
        if not isinstance(identity, ModelTokenizerIdentity):
            raise TypeError("model/tokenizer/template identity is required")
        self.identity = identity
        self.backend = backend
        self._counter = RuntimeTokenCounter(identity, backend) if backend is not None else Utf8ByteCounter()

    @property
    def unit(self) -> CountUnit:
        return "model_tokens" if self.backend is not None else "utf8_bytes"

    def exact_counter(self) -> RuntimeTokenCounter:
        """Expose a packer counter only when an exact backend is configured."""
        if self.backend is None:
            raise RuntimeError("no exact backend; estimate is UTF-8 bytes, not model tokens")
        return RuntimeTokenCounter(self.identity, self.backend)

    def cache_key(self, scope: SessionKey, rendered_prompt: str) -> str:
        """Session/model/template-bound application key; **not** a KV handle."""
        if not isinstance(scope, SessionKey):
            raise TypeError("explicit SessionKey required")
        if not isinstance(rendered_prompt, str):
            raise TypeError("rendered prompt must be text")
        fields = (
            scope.tenant_id, scope.owner_id, scope.agent_id, scope.session_id,
            self.identity.model, self.identity.tokenizer,
            self.identity.template, self.identity.revision, rendered_prompt,
        )
        return hashlib.sha256(json.dumps(fields, ensure_ascii=False).encode("utf-8")).hexdigest()

    def measure(self, rendered_prompt: str, *, scope: SessionKey) -> TokenMeasurement:
        if not isinstance(rendered_prompt, str):
            raise TypeError("rendered prompt must be text")
        value = self._counter.count(rendered_prompt)
        return TokenMeasurement(
            quantity=value, unit=self.unit, exact_backend=self.backend is not None,
            identity=self.identity,
            session_cache_key=self.cache_key(scope, rendered_prompt),
        )

    def assess(
        self,
        rendered_prompt: str,
        *,
        scope: SessionKey,
        limit: int,
        reserved: int = 0,
        guardband: int = 0,
        unit: CountUnit,
    ) -> BudgetAssessment:
        """Return fit assessment, refusing model-token/byte unit confusion."""
        if unit != self.unit:
            raise ValueError(f"budget unit {unit!r} incompatible with counter unit {self.unit!r}")
        for name, value in (("limit", limit), ("reserved", reserved), ("guardband", guardband)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        # Reuse the existing validated budget boundary (with guardband added
        # explicitly, never hidden as unreported tokens).
        TokenBudget(limit, reserved + guardband)
        return BudgetAssessment(self.measure(rendered_prompt, scope=scope), limit, reserved, guardband)

    def require_fit(self, rendered_prompt: str, *, scope: SessionKey,
                    limit: int, reserved: int = 0, guardband: int = 0,
                    unit: CountUnit) -> BudgetAssessment:
        assessment = self.assess(
            rendered_prompt, scope=scope, limit=limit,
            reserved=reserved, guardband=guardband, unit=unit,
        )
        if not assessment.fits:
            raise BudgetOverflow(
                f"rendered prompt requires {assessment.measurement.quantity} {unit}, "
                f"available {assessment.available} {unit}"
            )
        return assessment


__all__ = [
    "ModelTokenizerIdentity", "ExactTokenBackend", "TokenMeasurement", "BudgetAssessment",
    "RuntimeTokenCounter", "TokenBudgetAdapter",
]
