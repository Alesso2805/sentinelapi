"""AR-10: production refuses unsafe settings."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from sentinelapi.config import SentinelSettings

# A production configuration that starts. Each unsafe case changes one thing,
# so a test cannot pass because of some other refusal.
SAFE: dict[str, Any] = {
    "env": "production",
    "jwt_secret": "a-production-jwt-secret-of-32-bytes!",
    "audit_hash_key": "a-production-audit-hash-key-32-bytes",
    "backend": "redis",
}

UNSAFE: list[tuple[str, dict[str, Any]]] = [
    ("the example secret", {"jwt_secret": "change-me"}),
    ("the compose secret", {"jwt_secret": "change-me-in-production"}),
    ("a short secret", {"jwt_secret": "too-short"}),
    ("no audit hash key", {"audit_hash_key": None}),
    ("a short audit hash key", {"audit_hash_key": "short"}),
    ("the memory backend", {"backend": "memory"}),
]


def settings(**values: Any) -> SentinelSettings:
    return SentinelSettings(_env_file=None, **values)


def test_a_safe_production_configuration_starts() -> None:
    assert settings(**SAFE).env == "production"


@pytest.mark.parametrize("change", [c for _, c in UNSAFE], ids=[name for name, _ in UNSAFE])
def test_production_refuses_unsafe_settings(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="unsafe production settings"):
        settings(**{**SAFE, **change})


def test_every_problem_is_named_at_once() -> None:
    with pytest.raises(ValidationError) as refused:
        settings(env="production")
    message = str(refused.value)
    for setting in ("SENTINEL_JWT_SECRET", "SENTINEL_AUDIT_HASH_KEY", "SENTINEL_BACKEND"):
        assert setting in message


def test_the_memory_backend_can_be_allowed_on_purpose() -> None:
    assert settings(**{**SAFE, "backend": "memory", "allow_memory_backend": True}).backend == "memory"


def test_development_starts_with_the_defaults() -> None:
    assert settings().env == "development"


def test_a_typo_in_the_backend_fails_instead_of_meaning_memory() -> None:
    with pytest.raises(ValidationError):
        settings(backend="Redis")
