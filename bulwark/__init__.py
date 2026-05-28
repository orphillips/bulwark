"""Bulwark -- AI Agent Security Evaluation Framework."""

__version__ = "0.1.0"


def __getattr__(name: str):
    """Lazy-load SDK entry points so the package is importable before
    ``bulwark.sdk`` is implemented."""
    if name in ("evaluate", "evaluate_sync"):
        from bulwark.sdk import evaluate, evaluate_sync  # noqa: F811

        _map = {"evaluate": evaluate, "evaluate_sync": evaluate_sync}
        return _map[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["evaluate", "evaluate_sync", "__version__"]
