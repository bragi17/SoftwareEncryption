from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Self


class UserMode(str, Enum):
    OPERATOR = "operator"
    ADVANCED_ADMIN = "advanced_admin"

    @property
    def label(self) -> str:
        if self is UserMode.OPERATOR:
            return "Operator"
        return "Advanced Admin"


@dataclass
class OperationResult:
    success: bool
    message: str
    code: str | None = None
    detail: dict[str, object] = field(default_factory=dict)
    log_lines: list[str] = field(default_factory=list)

    @classmethod
    def ok(
        cls,
        message: str = "OK",
        *,
        detail: Mapping[str, object] | None = None,
        log_lines: Sequence[str] | None = None,
    ) -> Self:
        return cls(
            success=True,
            message=message,
            code=None,
            detail=dict(detail or {}),
            log_lines=list(log_lines or []),
        )

    @classmethod
    def fail(
        cls,
        message: str,
        *,
        code: str,
        detail: Mapping[str, object] | None = None,
        log_lines: Sequence[str] | None = None,
    ) -> Self:
        return cls(
            success=False,
            message=message,
            code=code,
            detail=dict(detail or {}),
            log_lines=list(log_lines or []),
        )


@dataclass
class ServerState:
    running: bool = False
    starting: bool = False
    base_url: str | None = None
    error: str | None = None

    @property
    def status_label(self) -> str:
        if self.error:
            return "error"
        if self.starting:
            return "starting"
        if self.running:
            return "running"
        return "stopped"


@dataclass
class ProjectState:
    mode: UserMode = UserMode.OPERATOR
    project_root: Path | None = None
    config_path: Path | None = None
    release_root: Path | None = None
    last_result: OperationResult | None = None
    server: ServerState = field(default_factory=ServerState)
