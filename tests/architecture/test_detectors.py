"""AR-17: detectors receive domain types and plain values, never a
framework object, so they stay usable from any framework."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import typing
from collections.abc import Callable, Iterator

import sentinelapi.detectors

FRAMEWORKS = ("starlette", "fastapi")


def public_callables() -> Iterator[tuple[str, Callable[..., object]]]:
    for info in pkgutil.iter_modules(sentinelapi.detectors.__path__, "sentinelapi.detectors."):
        module = importlib.import_module(info.name)
        for name, member in vars(module).items():
            if name.startswith("_") or getattr(member, "__module__", None) != module.__name__:
                continue
            if inspect.isfunction(member):
                yield f"{info.name}.{name}", member
            elif inspect.isclass(member):
                for method_name, method in vars(member).items():
                    if inspect.isfunction(method) and not method_name.startswith("_"):
                        yield f"{info.name}.{name}.{method_name}", method


def _types_in(annotation: object) -> Iterator[object]:
    yield annotation
    for arg in typing.get_args(annotation):
        yield from _types_in(arg)


def test_no_detector_takes_a_framework_object() -> None:
    offending = [
        f"{qualname}: {param}"
        for qualname, function in public_callables()
        for param, annotation in typing.get_type_hints(function).items()
        for t in _types_in(annotation)
        if getattr(t, "__module__", "").startswith(FRAMEWORKS)
    ]
    assert len(list(public_callables())) >= 5
    assert offending == []
