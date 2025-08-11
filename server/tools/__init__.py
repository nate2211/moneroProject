# giltools/__init__.py

from __future__ import annotations
from typing import TYPE_CHECKING
import importlib, sys, types

try:
    _ext = importlib.import_module(__name__ + ".giltools")  # loads tools/giltools*.pyd

    # expose module + alias at package level
    giltools = _ext
    gilltools = _ext  # alias

    # IMPORTANT: register the alias as a real submodule for `import tools.gilltools`
    sys.modules[__name__ + ".gilltools"] = _ext

    # re-export functions at package level
    yield_no_gil = _ext.yield_no_gil
    burn_no_gil = _ext.burn_no_gil
    wait_handle_no_gil = getattr(
        _ext,
        "wait_handle_no_gil",
        lambda *a, **k: (_ for _ in ()).throw(
            NotImplementedError("wait_handle_no_gil is only available on Windows.")
        ),
    )
    unhinge_process = _ext.unhinge_process
    start_cpu_boost = _ext.start_cpu_boost
    stop_cpu_boost = _ext.stop_cpu_boost
    is_cpu_boost_running = _ext.is_cpu_boost_running

    # make attribute access/dir delegate to the extension for better UX/autocomplete
    def __getattr__(name: str):
        try:
            return getattr(_ext, name)
        except AttributeError:
            raise

    def __dir__():
        return sorted(set(list(globals().keys()) + dir(_ext)))

except Exception as e:
    # Extension not available yet: define placeholders
    def _missing(*_a, **_k):
        raise ImportError(f"tools.giltools extension failed to load: {e}")

    class _MissingModule(types.ModuleType):
        def __getattr__(self, _n):  # type: ignore[override]
            return _missing

    giltools = _MissingModule("tools.giltools")  # type: ignore[assignment]
    gilltools = giltools
    yield_no_gil = _missing        # type: ignore[assignment]
    burn_no_gil = _missing         # type: ignore[assignment]
    wait_handle_no_gil = _missing  # type: ignore[assignment]
    unhinge_process = _missing     # type: ignore[assignment]
    start_cpu_boost = _missing     # type: ignore[assignment]
    stop_cpu_boost = _missing      # type: ignore[assignment]
    is_cpu_boost_running = _missing # type: ignore[assignment]



__all__ = [
    "giltools",
    "gilltools",
    "yield_no_gil",
    "burn_no_gil",
    "wait_handle_no_gil",
    "unhinge_process",
    "start_cpu_boost",
    "stop_cpu_boost",
    "is_cpu_boost_running",
]