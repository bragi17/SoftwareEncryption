"""Project scanner for building protection manifests."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath, PureWindowsPath

from skeyprotect.config import SKeyConfig


@dataclass(frozen=True)
class EntryPoint:
    id: str
    path: str
    kind: str
    feature: str


@dataclass(frozen=True)
class ProtectedBlob:
    id: str
    path: str
    kind: str
    feature: str
    mode: str | None = None


@dataclass(frozen=True)
class ScanResult:
    entrypoints: dict[str, EntryPoint] = field(default_factory=dict)
    blobs: dict[str, ProtectedBlob] = field(default_factory=dict)
    module_map: dict[str, str | None] = field(default_factory=dict)


def scan_project(root: Path, config: SKeyConfig) -> ScanResult:
    project_root = root.resolve(strict=False)
    entrypoints: dict[str, EntryPoint] = {}
    blobs: dict[str, ProtectedBlob] = {}
    module_map: dict[str, str | None] = {}
    python_entry_features: dict[str, str] = {}

    for python_entry in config.python.entries:
        posix_path = _contained_config_path(project_root, python_entry.path)
        python_entry_features[posix_path] = python_entry.feature
        entry_id = f"python:{posix_path}"
        entrypoints[entry_id] = EntryPoint(
            id=entry_id,
            path=posix_path,
            kind="python",
            feature=python_entry.feature,
        )

    for exe_entry in config.exe.entries:
        posix_path = _contained_config_path(project_root, exe_entry.path)
        entry_id = f"exe:{posix_path}"
        entrypoints[entry_id] = EntryPoint(
            id=entry_id,
            path=posix_path,
            kind="exe",
            feature=exe_entry.feature,
        )
        blobs[entry_id] = ProtectedBlob(
            id=entry_id,
            path=posix_path,
            kind="exe",
            feature=exe_entry.feature,
        )
        for dep_path in _expand_patterns(project_root, exe_entry.include_deps, []):
            blob_id = f"exe-dep:{dep_path}"
            blobs[blob_id] = ProtectedBlob(
                id=blob_id,
                path=dep_path,
                kind="exe-dep",
                feature=exe_entry.feature,
            )

    for jar_entry in config.jar.entries:
        posix_path = _contained_config_path(project_root, jar_entry.path)
        entry_id = f"jar:{posix_path}"
        entrypoints[entry_id] = EntryPoint(
            id=entry_id,
            path=posix_path,
            kind="jar",
            feature=jar_entry.feature,
        )
        blobs[entry_id] = ProtectedBlob(
            id=entry_id,
            path=posix_path,
            kind="jar",
            feature=jar_entry.feature,
        )

    for resource_entry in config.resources.entries:
        posix_path = _contained_config_path(project_root, resource_entry.path)
        entry_id = f"res:{posix_path}"
        entrypoints[entry_id] = EntryPoint(
            id=entry_id,
            path=posix_path,
            kind="resource",
            feature=resource_entry.feature,
        )
        blobs[entry_id] = ProtectedBlob(
            id=entry_id,
            path=posix_path,
            kind="resource",
            feature=resource_entry.feature,
            mode=resource_entry.mode,
        )

    module_feature = config.python.entries[0].feature if config.python.entries else ""
    for module_path in _expand_patterns(
        project_root,
        config.python.modules.include,
        config.python.modules.exclude,
    ):
        feature = python_entry_features.get(module_path, module_feature)
        blob_id = _add_python_blob(blobs, module_path, feature)
        module_map[_module_name(module_path)] = blob_id

    for hidden_import in config.python.hidden_imports:
        hidden_paths = _resolve_hidden_import(project_root, hidden_import)
        if not hidden_paths:
            module_map.setdefault(hidden_import, None)
            continue

        for hidden_path in hidden_paths:
            feature = python_entry_features.get(hidden_path, module_feature)
            blob_id = _add_python_blob(blobs, hidden_path, feature)
            module_map[_module_name(hidden_path)] = blob_id

    return ScanResult(entrypoints=entrypoints, blobs=blobs, module_map=module_map)


def _contained_config_path(project_root: Path, configured_path: str) -> str:
    path = Path(configured_path)
    candidate = path if path.is_absolute() else project_root / path
    resolved = candidate.resolve(strict=False)

    if not resolved.is_relative_to(project_root):
        raise ValueError(f"path escapes project root: {configured_path}")

    return resolved.relative_to(project_root).as_posix()


def _expand_patterns(project_root: Path, includes: list[str], excludes: list[str]) -> list[str]:
    paths: set[str] = set()
    for pattern in includes:
        _reject_external_pattern(pattern)
        for matched_path in project_root.glob(pattern):
            if not matched_path.is_file():
                continue
            posix_path = _contained_config_path(project_root, str(matched_path))
            if not _is_excluded(posix_path, excludes):
                paths.add(posix_path)

    return sorted(paths)


def _add_python_blob(
    blobs: dict[str, ProtectedBlob],
    module_path: str,
    feature: str,
) -> str:
    blob_id = f"py:{module_path}"
    blobs.setdefault(
        blob_id,
        ProtectedBlob(
            id=blob_id,
            path=module_path,
            kind="python",
            feature=feature,
        ),
    )
    return blob_id


def _resolve_hidden_import(project_root: Path, hidden_import: str) -> list[str]:
    parts = hidden_import.split(".")
    if any(not part or part in {".", ".."} or "/" in part or "\\" in part for part in parts):
        return []

    module_paths: list[str] = []
    for depth in range(1, len(parts)):
        package_init = project_root.joinpath(*parts[:depth], "__init__.py")
        if package_init.is_file():
            module_paths.append(_contained_config_path(project_root, str(package_init)))

    module_root = project_root.joinpath(*parts)
    package_init = module_root / "__init__.py"
    module_file = module_root.with_suffix(".py")
    if package_init.is_file():
        module_paths.append(_contained_config_path(project_root, str(package_init)))
    elif module_file.is_file():
        module_paths.append(_contained_config_path(project_root, str(module_file)))
    else:
        return []

    return module_paths


def _reject_external_pattern(pattern: str) -> None:
    if Path(pattern).is_absolute() or PureWindowsPath(pattern).is_absolute():
        raise ValueError(f"glob pattern escapes project root: {pattern}")

    path = PurePosixPath(pattern.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"glob pattern escapes project root: {pattern}")


def _is_excluded(path: str, excludes: list[str]) -> bool:
    return any(fnmatch(path, pattern.replace("\\", "/")) for pattern in excludes)


def _module_name(path: str) -> str:
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)
