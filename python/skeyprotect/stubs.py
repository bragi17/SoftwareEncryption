"""Generated Python entry stubs for protected release layouts."""

from __future__ import annotations

import json
from pathlib import Path

from skeyprotect.scanner import EntryPoint

BOOTSTRAP_FILENAME = "skey_bootstrap.py"


def write_python_entry_stub(product_root: Path, entrypoint: EntryPoint) -> Path:
    """Write a Python entry stub that delegates startup to skey_bootstrap."""
    stub_path = product_root / Path(entrypoint.path)
    stub_path.parent.mkdir(parents=True, exist_ok=True)
    stub_path.write_text(_entry_stub_source(entrypoint.id, entrypoint.feature), encoding="utf-8")
    return stub_path


def write_python_envelope_stub(product_root: Path, relative_path: str, feature: str) -> Path:
    """Write a Sentinel-style runnable Python shell for one protected source file."""
    stub_path = product_root / Path(relative_path)
    stub_path.parent.mkdir(parents=True, exist_ok=True)
    blob_id = f"py:{Path(relative_path).as_posix()}"
    stub_path.write_text(_protected_file_stub_source(blob_id, feature), encoding="utf-8")
    return stub_path


def write_bootstrap(product_root: Path) -> Path:
    """Write the shared bootstrap module used by generated Python stubs."""
    bootstrap_path = product_root / BOOTSTRAP_FILENAME
    bootstrap_path.write_text(_bootstrap_source(), encoding="utf-8")
    return bootstrap_path


def _entry_stub_source(entry_id: str, feature: str) -> str:
    entry_id_literal = json.dumps(entry_id)
    feature_literal = json.dumps(feature)
    return f'''"""Generated bootstrap stub for a protected Python entry."""

from __future__ import annotations

from pathlib import Path
import sys

_ENTRY_FILE = Path(__file__).resolve()
for _candidate in (_ENTRY_FILE.parent, *_ENTRY_FILE.parents):
    if (_candidate / "skey_bootstrap.py").is_file():
        sys.path.insert(0, str(_candidate))
        break
else:
    raise RuntimeError("skey_bootstrap.py was not found in this release layout")

from skey_bootstrap import run_entry

_exit_code = run_entry({entry_id_literal}, {feature_literal}, __file__, __name__)
if __name__ == "__main__":
    raise SystemExit(_exit_code)
if _exit_code:
    raise RuntimeError(f"skey bootstrap failed with status {{_exit_code}}")
'''


def _protected_file_stub_source(blob_id: str, feature: str) -> str:
    blob_id_literal = json.dumps(blob_id)
    feature_literal = json.dumps(feature)
    return f'''"""Generated SKey protected Python launcher."""

from __future__ import annotations

from pathlib import Path
import sys

_ENTRY_FILE = Path(__file__).resolve()
for _candidate in (_ENTRY_FILE.parent, *_ENTRY_FILE.parents):
    if (_candidate / "skey_bootstrap.py").is_file():
        sys.path.insert(0, str(_candidate))
        break
else:
    raise RuntimeError("skey_bootstrap.py was not found in this release layout")

from skey_bootstrap import run_protected_file

_exit_code = run_protected_file({blob_id_literal}, {feature_literal}, __file__, __name__)
if __name__ == "__main__":
    raise SystemExit(_exit_code)
if _exit_code:
    raise RuntimeError(f"skey bootstrap failed with status {{_exit_code}}")
'''


def _bootstrap_source() -> str:
    return '''"""Runtime bootstrap for protected Python release entries."""

from __future__ import annotations

import atexit
import ctypes
import importlib.abc
import importlib.machinery
import json
import os
from pathlib import Path
import platform
import sys

_OK = 0
_LICENSE_MISSING = -1001
_SESSION_ENV = "APP_SKEY_SESSION"
_RUNTIME = None
_CTX = None
_DLL_DIRECTORY_HANDLES = []
# Rust currently maps unresolved module blobs to "decrypt failed"; keep this
# fallback list narrow so runtime and security failures abort imports.
_MODULE_NOT_FOUND_ERRORS = frozenset({"decrypt failed", "module not found", "blob not found"})


class _SkeyInitOptions(ctypes.Structure):
    _fields_ = [
        ("app_root", ctypes.c_char_p),
        ("payload_path", ctypes.c_char_p),
        ("entry_id", ctypes.c_char_p),
        ("original_path", ctypes.c_char_p),
        ("argv_json", ctypes.c_char_p),
        ("env_session", ctypes.c_char_p),
    ]


class _SkeyBuffer(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("len", ctypes.c_size_t),
    ]


class SecureMetaFinder(importlib.abc.MetaPathFinder):
    """Resolve protected Python modules through the SKey runtime."""

    def __init__(self, runtime: _RuntimeBridge, product_root: Path) -> None:
        self._runtime = runtime
        self._product_root = product_root

    def find_spec(
        self,
        fullname: str,
        path: object | None = None,
        target: object | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        resolution = self._runtime.find_module(fullname)
        if resolution is None:
            return None

        origin, is_package = _module_resolution_origin(self._product_root, resolution)
        loader = SecureLoader(self._runtime, fullname, origin, is_package)
        spec = importlib.machinery.ModuleSpec(
            fullname,
            loader,
            origin=origin,
            is_package=is_package,
        )
        if is_package:
            spec.submodule_search_locations = [str(Path(origin).parent)]
        return spec


class SecureLoader(importlib.abc.Loader):
    """Load protected Python module source through the SKey runtime."""

    def __init__(
        self,
        runtime: _RuntimeBridge,
        fullname: str,
        origin: str,
        is_package: bool,
    ) -> None:
        self._runtime = runtime
        self._fullname = fullname
        self._origin = origin
        self._is_package = is_package

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> None:
        del spec
        return None

    def exec_module(self, module: object) -> None:
        source = self._runtime.load_module(self._fullname)
        module.__file__ = self._origin
        module.__loader__ = self
        module.__package__ = self._fullname if self._is_package else self._fullname.rpartition(".")[0]
        module.__spec__.origin = self._origin
        if self._is_package:
            locations = [str(Path(self._origin).parent)]
            module.__path__ = locations
            module.__spec__.submodule_search_locations = locations
        exec(compile(source, self._origin, "exec"), module.__dict__)


class _RuntimeBridge:
    def __init__(self, library: ctypes.CDLL, ctx: ctypes.c_void_p) -> None:
        self._library = library
        self._ctx = ctx

    def check_license(self, feature: str) -> int:
        return int(self._library.skey_license_check(self._ctx, _cstr(feature)))

    def load_entry(self, entry_id: str) -> str:
        return self._load_buffered(self._library.skey_load_entry, entry_id)

    def find_module(self, fullname: str) -> dict[str, object] | None:
        buffer = _SkeyBuffer()
        status = int(self._library.skey_find_module(self._ctx, _cstr(fullname), ctypes.byref(buffer)))
        if status != _OK:
            message = _last_error(self._library)
            if _is_module_not_found_error(message):
                return None
            raise RuntimeError(f"E_SKEY_RUNTIME: {message}")
        try:
            try:
                resolution = json.loads(_buffer_bytes(buffer).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("E_SKEY_RUNTIME: malformed module metadata") from exc
            if not isinstance(resolution, dict):
                raise RuntimeError("E_SKEY_RUNTIME: malformed module metadata")
            return resolution
        finally:
            self._library.skey_buffer_free(buffer)

    def load_module(self, fullname: str) -> str:
        return self._load_buffered(self._library.skey_load_module, fullname)

    def create_session(self) -> str:
        buffer = _SkeyBuffer()
        status = int(self._library.skey_create_session(self._ctx, ctypes.byref(buffer)))
        if status != _OK:
            raise RuntimeError(f"E_SKEY_RUNTIME: {_last_error(self._library)}")
        try:
            return _buffer_bytes(buffer).decode("utf-8")
        finally:
            self._library.skey_buffer_free(buffer)

    def _load_buffered(self, function: object, value: str) -> str:
        buffer = _SkeyBuffer()
        status = int(function(self._ctx, _cstr(value), ctypes.byref(buffer)))
        if status != _OK:
            raise RuntimeError(f"E_SKEY_RUNTIME: {_last_error(self._library)}")
        try:
            return _buffer_bytes(buffer).decode("utf-8")
        finally:
            self._library.skey_buffer_free(buffer)


def run_protected_file(blob_id: str, feature: str, entry_file: str, module_name: str) -> int:
    """Initialize the runtime, decrypt one protected file, and execute it in-place."""
    entry_path = Path(entry_file).resolve()
    product_root = _find_product_root(entry_path)
    if str(product_root) not in sys.path:
        sys.path.insert(0, str(product_root))

    runtime = _initialize_runtime(product_root, blob_id, entry_path)
    status = runtime.check_license(feature)
    if status == _LICENSE_MISSING:
        _report_runtime_error("SKey 授权缺失：请先激活授权或插入加密狗后再运行。")
        return 2
    if status != _OK:
        _report_runtime_error(f"SKey runtime error: {_last_error(_RUNTIME)}")
        return 1

    if not os.environ.get(_SESSION_ENV):
        os.environ[_SESSION_ENV] = runtime.create_session()

    _install_import_hook(runtime, product_root)
    source = runtime.load_entry(blob_id)
    _execute_entry_source(source, entry_path, module_name, product_root, runtime)
    return 0


def run_entry(entry_id: str, feature: str, entry_file: str, entry_module_name: str = "__main__") -> int:
    """Initialize the SKey runtime and execute a protected Python entry."""
    entry_path = Path(entry_file).resolve()
    product_root = _find_product_root(entry_path)
    if str(product_root) not in sys.path:
        sys.path.insert(0, str(product_root))

    runtime = _initialize_runtime(product_root, entry_id, entry_path)
    status = runtime.check_license(feature)
    if status == _LICENSE_MISSING:
        sys.stderr.write("E_LICENSE_MISSING: activation required\\n")
        return 2
    if status != _OK:
        sys.stderr.write(f"E_SKEY_RUNTIME: {_last_error(_RUNTIME)}\\n")
        return 1

    if not os.environ.get(_SESSION_ENV):
        os.environ[_SESSION_ENV] = runtime.create_session()

    _install_import_hook(runtime, product_root)
    source = runtime.load_entry(entry_id)
    _execute_entry_source(source, entry_path, entry_module_name, product_root, runtime)
    return 0


def _initialize_runtime(product_root: Path, entry_id: str, entry_path: Path) -> _RuntimeBridge:
    global _CTX, _RUNTIME
    if _RUNTIME is not None and _CTX is not None and _CTX.value:
        return _RuntimeBridge(_RUNTIME, _CTX)

    library = _load_library(product_root)
    ctx = ctypes.c_void_p()
    env_session = os.environ.get(_SESSION_ENV)
    options = _SkeyInitOptions(
        _cpath(product_root),
        _cpath(_payload_path(product_root)),
        _cstr(entry_id),
        _cpath(entry_path),
        _cstr(json.dumps(sys.argv, ensure_ascii=False)),
        _cstr(env_session) if env_session else None,
    )
    status = int(library.skey_runtime_init(ctypes.byref(options), ctypes.byref(ctx)))
    if status != _OK:
        sys.stderr.write(f"E_SKEY_RUNTIME: {_last_error(library)}\\n")
        raise SystemExit(1)
    _RUNTIME = library
    _CTX = ctx
    bridge = _RuntimeBridge(library, ctx)
    atexit.register(_free_context)
    return bridge


def _report_runtime_error(message: str) -> None:
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(None, message, "SKey Protection", 0x10)
            return
        except Exception:
            pass
    sys.stderr.write(message + "\\n")


def _load_library(product_root: Path) -> ctypes.CDLL:
    runtime_path = (product_root / ".secure" / "rt" / _runtime_library_name()).resolve()
    if not runtime_path.is_file():
        raise RuntimeError("SKey runtime library was not found")
    runtime_dir = str(runtime_path.parent)
    os.environ["PATH"] = f"{runtime_dir}{os.pathsep}{os.environ.get('PATH', '')}"
    if hasattr(os, "add_dll_directory"):
        _DLL_DIRECTORY_HANDLES.append(os.add_dll_directory(runtime_dir))
    library = ctypes.WinDLL(str(runtime_path)) if os.name == "nt" else ctypes.CDLL(str(runtime_path))
    _configure_library(library)
    return library


def _configure_library(library: ctypes.CDLL) -> None:
    library.skey_runtime_init.argtypes = [
        ctypes.POINTER(_SkeyInitOptions),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.skey_runtime_init.restype = ctypes.c_int
    library.skey_license_check.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    library.skey_license_check.restype = ctypes.c_int
    for name in ("skey_load_entry", "skey_find_module", "skey_load_module"):
        function = getattr(library, name)
        function.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(_SkeyBuffer)]
        function.restype = ctypes.c_int
    library.skey_create_session.argtypes = [ctypes.c_void_p, ctypes.POINTER(_SkeyBuffer)]
    library.skey_create_session.restype = ctypes.c_int
    library.skey_buffer_free.argtypes = [_SkeyBuffer]
    library.skey_buffer_free.restype = None
    library.skey_context_free.argtypes = [ctypes.c_void_p]
    library.skey_context_free.restype = None
    library.skey_last_error_message.argtypes = []
    library.skey_last_error_message.restype = ctypes.c_char_p


def _install_import_hook(runtime: _RuntimeBridge, product_root: Path) -> None:
    sys.meta_path = [finder for finder in sys.meta_path if not isinstance(finder, SecureMetaFinder)]
    sys.meta_path.insert(0, SecureMetaFinder(runtime, product_root))


def _execute_entry_source(
    source: str,
    entry_path: Path,
    entry_module_name: str,
    product_root: Path,
    runtime: _RuntimeBridge,
) -> None:
    module_name = entry_module_name or "__main__"
    module = sys.modules.get(module_name)
    if module is None:
        import types

        module = types.ModuleType(module_name)
        sys.modules[module_name] = module
    package = _entry_package(product_root, entry_path, runtime)
    module.__dict__.update(
        {
            "__name__": module_name,
            "__file__": str(entry_path),
            "__package__": package,
            "__loader__": None,
            "__spec__": None,
        }
    )
    exec(compile(source, str(entry_path), "exec"), module.__dict__)


def _entry_package(product_root: Path, entry_path: Path, runtime: _RuntimeBridge) -> str:
    try:
        relative = entry_path.relative_to(product_root)
    except ValueError:
        return ""
    parent_parts = list(relative.parent.parts)
    if entry_path.name == "__init__.py":
        return ".".join(parent_parts)
    for end in range(len(parent_parts), 0, -1):
        candidate = ".".join(parent_parts[:end])
        resolution = runtime.find_module(candidate)
        if resolution is not None and _module_resolution_origin(product_root, resolution)[1]:
            return candidate
    return ""


def _is_module_not_found_error(message: str) -> bool:
    return message.strip().lower() in _MODULE_NOT_FOUND_ERRORS


def _module_resolution_origin(product_root: Path, resolution: dict[str, object]) -> tuple[str, bool]:
    virtual_filename = resolution.get("virtual_filename")
    is_package = resolution.get("is_package")
    blob_id = resolution.get("blob_id")
    if not isinstance(virtual_filename, str) or not virtual_filename:
        raise RuntimeError("E_SKEY_RUNTIME: malformed module metadata")
    if not isinstance(is_package, bool):
        raise RuntimeError("E_SKEY_RUNTIME: malformed module metadata")
    if blob_id is not None and not isinstance(blob_id, str):
        raise RuntimeError("E_SKEY_RUNTIME: malformed module metadata")

    virtual_path = Path(virtual_filename)
    if virtual_path.is_absolute() or virtual_path.drive or virtual_path.root or ".." in virtual_path.parts:
        raise RuntimeError("E_SKEY_RUNTIME: malformed module metadata")

    product_root = product_root.resolve()
    origin = (product_root / virtual_path).resolve()
    try:
        origin.relative_to(product_root)
    except ValueError as exc:
        raise RuntimeError("E_SKEY_RUNTIME: malformed module metadata") from exc
    return str(origin), is_package


def _payload_path(product_root: Path) -> Path:
    secure_root = product_root / ".secure"
    preferred = secure_root / "payload.skp"
    if preferred.is_file():
        return preferred
    candidates = sorted(secure_root.glob("*.skp"))
    if len(candidates) == 1:
        return candidates[0]
    raise RuntimeError("SKey payload was not found")


def _runtime_library_name() -> str:
    system = platform.system()
    if system == "Windows":
        return "skey_rt.dll"
    if system == "Darwin":
        return "libskey_rt.dylib"
    return "libskey_rt.so"


def _buffer_bytes(buffer: _SkeyBuffer) -> bytes:
    if not buffer.data or buffer.len == 0:
        return b""
    return ctypes.string_at(buffer.data, buffer.len)


def _last_error(library: ctypes.CDLL | None) -> str:
    if library is None:
        return "runtime error"
    message = library.skey_last_error_message()
    if not message:
        return "runtime error"
    return message.decode("utf-8", errors="replace")


def _free_context() -> None:
    global _CTX
    if _RUNTIME is not None and _CTX is not None and _CTX.value:
        _RUNTIME.skey_context_free(_CTX)
        _CTX = None


def _cstr(value: str | None) -> bytes | None:
    if value is None:
        return None
    return value.encode("utf-8")


def _cpath(path: Path) -> bytes:
    return str(path).encode("utf-8")


def _find_product_root(entry_file: Path) -> Path:
    """Walk upward from an entry file until the release .secure directory is found."""
    for candidate in (entry_file.parent, *entry_file.parents):
        if (candidate / ".secure").is_dir():
            return candidate
    raise RuntimeError("release .secure directory was not found")
'''
