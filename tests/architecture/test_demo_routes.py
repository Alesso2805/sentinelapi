"""AR-14: the demo app's routes declare response models and require
authentication, except the public ones of SPEC › Demo app API contract."""

from __future__ import annotations

import typing

import pytest
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from fastapi.security.base import SecurityBase
from pydantic import BaseModel

from examples.demo_app.main import create_app

PUBLIC_PATHS = {"/health", "/ready", "/auth/login", "/auth/refresh"}
PUBLIC_PREFIXES = ("/demo/",)


def api_routes() -> list[APIRoute]:
    routes = [r for r in create_app().routes if isinstance(r, APIRoute)]
    assert routes
    return routes


def _is_model(annotation: object) -> bool:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return True
    return typing.get_origin(annotation) is list and _is_model(typing.get_args(annotation)[0])


def _requires_auth(dependant: Dependant) -> bool:
    return any(isinstance(d.call, SecurityBase) or _requires_auth(d) for d in dependant.dependencies)


def _is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


@pytest.mark.xfail(strict=True, reason="SEN-26: /me, /health and /security/events return plain dicts")
def test_every_route_declares_a_response_model() -> None:
    assert [r.path for r in api_routes() if not _is_model(r.response_model)] == []


@pytest.mark.xfail(strict=True, reason="SEN-26: /security/events is public")
def test_every_private_route_requires_authentication() -> None:
    unprotected = [r.path for r in api_routes() if not _is_public(r.path) and not _requires_auth(r.dependant)]
    assert unprotected == []
