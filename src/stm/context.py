"""Deterministic, bounded prompt-context packing for short-term memory.

This component is deliberately free of model, database, and network dependencies.
It operates on items already authorized for the requesting identity/session;
authorization and prompt-injection defense belong to the caller.

The default counter measures UTF-8 *bytes*, not model tokens. This gives a
conservative byte-bound for most byte-fallback tokenizers, but it is not a
guarantee about any particular model's prompt usage (chat templates and model
special tokens must also be accounted for). Inject a model-specific counter
when exact model-token accounting is required.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
from typing import Callable, Iterable, Protocol


class BudgetOverflow(ValueError):
    """The required pinned/protected context cannot fit the provided budget."""


class TokenCounter(Protocol):
    """Count tokens in a *fully rendered* prompt text, including separators."""

    def count(self, text: str) -> int: ...


class Utf8ByteCounter:
    """Conservative model-independent byte count; NOT a model token count."""

    def count(self, text: str) -> int:
        return len(text.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class TokenBudget:
    limit: int
    reserved: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or self.limit < 0:
            raise ValueError("limit must be a nonnegative integer")
        if isinstance(self.reserved, bool) or not isinstance(self.reserved, int) or self.reserved < 0:
            raise ValueError("reserved must be a nonnegative integer")
        if self.reserved > self.limit:
            raise ValueError("reserved cannot exceed limit")

    @property
    def available(self) -> int:
        return self.limit - self.reserved


_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


@dataclass(frozen=True, slots=True)
class ContextItem:
    id: str
    text: str
    score: float = 0.0
    created_at: float = 0.0
    pinned: bool = False
    protected: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or _SAFE_ID.fullmatch(self.id) is None:
            raise ValueError("id must contain 1-128 safe ASCII ID characters")
        if not isinstance(self.text, str):
            raise ValueError("text must be a string")
        if not isinstance(self.score, (float, int)) or not math.isfinite(self.score):
            raise ValueError("score must be a finite number")
        if not isinstance(self.created_at, (float, int)) or not math.isfinite(self.created_at):
            raise ValueError("created_at must be a finite number")
        if not isinstance(self.pinned, bool) or not isinstance(self.protected, bool):
            raise ValueError("pinned and protected must be booleans")

    @property
    def required(self) -> bool:
        return self.pinned or self.protected


@dataclass(frozen=True, slots=True)
class PackedContext:
    text: str
    used_tokens: int
    available_tokens: int
    included_ids: tuple[str, ...]
    omitted_ids: tuple[str, ...]

    @property
    def free_tokens(self) -> int:
        return self.available_tokens - self.used_tokens


def render_context(items: Iterable[ContextItem]) -> str:
    """Render evidence with escaped body controls so labels cannot be spoofed.

    Escaping newlines, backslashes and controls prevents one stored message
    from manufacturing a fake second `[id]` entry in the packed block. It is
    structural quoting, not a general prompt-injection defense.
    """
    return "\n".join(_render_item(item) for item in items)


def _render_item(item: ContextItem) -> str:
    # JSON string escaping gives a readable one-line body. Strip surrounding
    # string quotes to preserve the compact `[id] body` representation.
    escaped = json.dumps(item.text, ensure_ascii=False)[1:-1]
    # JSON's required control escaping does not cover Unicode line separators.
    # Escape those too so the provenance block stays one physical line/item.
    escaped = (escaped.replace("\u0085", r"\u0085")
                      .replace("\u2028", r"\u2028")
                      .replace("\u2029", r"\u2029"))
    return f"[{item.id}] {escaped}"


class ContextPacker:
    """Greedy deterministic ranking, then chronological presentation.

    Ranking uses descending score, descending timestamp, then ascending ID.
    Required items (pinned OR protected) are always included, or the method
    raises BudgetOverflow without returning partial context. Optional items
    too large to fit are omitted whole; no text is silently truncated.

    The built-in byte-counter/renderer path is O(N log N), including sort.
    For custom counters/renderers, rendered text is re-counted after every
    prospective inclusion so non-additive model tokenizers remain accurate.
    That fallback is O(N^2) in the worst case, intended for bounded working
    memory candidate sets rather than bulk document ingestion.
    """

    def __init__(
        self,
        counter: TokenCounter | None = None,
        renderer: Callable[[Iterable[ContextItem]], str] = render_context,
    ) -> None:
        self.counter = counter if counter is not None else Utf8ByteCounter()
        self.renderer = renderer

    def _count(self, text: str) -> int:
        tokens = self.counter.count(text)
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ValueError("token counter must return a nonnegative integer")
        return tokens

    def pack(self, items: Iterable[ContextItem], budget: TokenBudget) -> PackedContext:
        if not isinstance(budget, TokenBudget):
            raise TypeError("budget must be a TokenBudget")
        candidates = tuple(items)
        if any(not isinstance(item, ContextItem) for item in candidates):
            raise TypeError("items must contain ContextItem instances")
        ids = [item.id for item in candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate item ID")

        # Ordering is stable across Python processes, input permutations, and
        # dict insertion order; IDs break exact score/timestamp ties.
        def present_order(item: ContextItem) -> tuple[float, str]:
            return item.created_at, item.id

        selected = [item for item in candidates if item.required]
        selected.sort(key=present_order)
        text = self.renderer(selected)
        used = self._count(text)
        if used > budget.available:
            required_ids = ", ".join(item.id for item in selected)
            raise BudgetOverflow(
                f"required context ({required_ids}) needs {used} units, "
                f"but only {budget.available} are available"
            )

        optional = sorted(
            (item for item in candidates if not item.required),
            key=lambda item: (-item.score, -item.created_at, item.id),
        )
        omitted: list[str] = []
        if isinstance(self.counter, Utf8ByteCounter) and self.renderer is render_context:
            # Item text plus one separator for every non-initial item is
            # exactly additive under the default UTF-8 byte count.
            for item in optional:
                increment = len(_render_item(item).encode("utf-8")) + bool(selected)
                if used + increment <= budget.available:
                    selected.append(item)
                    used += increment
                else:
                    omitted.append(item.id)
            selected.sort(key=present_order)
            text = self.renderer(selected)
        else:
            for item in optional:
                trial = sorted((*selected, item), key=present_order)
                rendered = self.renderer(trial)
                trial_count = self._count(rendered)
                if trial_count <= budget.available:
                    selected, text, used = trial, rendered, trial_count
                else:
                    omitted.append(item.id)

        return PackedContext(
            text=text,
            used_tokens=used,
            available_tokens=budget.available,
            included_ids=tuple(item.id for item in selected),
            omitted_ids=tuple(omitted),
        )


__all__ = [
    "BudgetOverflow", "TokenCounter", "Utf8ByteCounter", "TokenBudget",
    "ContextItem", "PackedContext", "ContextPacker", "render_context",
]
