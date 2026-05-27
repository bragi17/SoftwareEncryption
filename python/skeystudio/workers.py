"""Background worker helpers for SKey Studio actions."""

from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar, cast

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QWidget


T = TypeVar("T")


class StudioWorker(QObject, Generic[T]):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, task: Callable[[], T]) -> None:
        super().__init__()
        self._task = task

    @Slot()
    def run(self) -> None:
        try:
            self.finished.emit(self._task())
        except Exception as exc:
            self.failed.emit(str(exc))


class _TaskResultDispatcher(QObject, Generic[T]):
    def __init__(
        self,
        thread: QThread,
        on_finished: Callable[[T], None],
        on_failed: Callable[[str], None] | None,
        set_disabled: Callable[[bool], None],
    ) -> None:
        super().__init__()
        self._thread = thread
        self._on_finished = on_finished
        self._on_failed = on_failed
        self._set_disabled = set_disabled

    @Slot(object)
    def finish(self, raw_result: object) -> None:
        self._set_disabled(False)
        self._on_finished(cast(T, raw_result))
        self._thread.quit()

    @Slot(str)
    def fail(self, message: str) -> None:
        self._set_disabled(False)
        if self._on_failed is not None:
            self._on_failed(message)
        self._thread.quit()


def run_background_task(
    owner: QObject,
    task: Callable[[], T],
    on_finished: Callable[[T], None],
    on_failed: Callable[[str], None] | None = None,
    disabled_widgets: tuple[QWidget, ...] = (),
) -> StudioWorker[T]:
    thread = QThread(owner)
    worker = StudioWorker(task)
    worker.moveToThread(thread)

    def set_disabled(disabled: bool) -> None:
        for widget in disabled_widgets:
            widget.setDisabled(disabled)

    dispatcher = _TaskResultDispatcher(thread, on_finished, on_failed, set_disabled)
    handles = _owner_worker_handles(owner)
    handles.append((thread, worker, dispatcher))

    def cleanup() -> None:
        try:
            handles.remove((thread, worker, dispatcher))
        except ValueError:
            pass

    set_disabled(True)
    thread.started.connect(worker.run)
    worker.finished.connect(dispatcher.finish)
    worker.failed.connect(dispatcher.fail)
    worker.finished.connect(worker.deleteLater)
    worker.failed.connect(worker.deleteLater)
    thread.finished.connect(cleanup)
    thread.finished.connect(dispatcher.deleteLater)
    thread.finished.connect(thread.deleteLater)
    thread.start()
    return worker


def _owner_worker_handles(owner: QObject) -> list[tuple[QThread, QObject, QObject]]:
    attribute_name = "_studio_background_tasks"
    existing = getattr(owner, attribute_name, None)
    if isinstance(existing, list):
        return cast(list[tuple[QThread, QObject, QObject]], existing)
    handles: list[tuple[QThread, QObject, QObject]] = []
    setattr(owner, attribute_name, handles)
    return handles
