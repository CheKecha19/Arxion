"""Фоновые задания: GUI получает события только при явном poll."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from queue import Empty, Queue
from threading import Lock, Thread
from uuid import UUID, uuid4

from pydantic import ValidationError

from firewall_compliance.parsers.registry import AmbiguousParserError, ParserContractError


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass(frozen=True)
class JobError:
    """Безопасная диагностика без содержимого исключения или исходного файла."""

    category: str
    message: str


@dataclass(frozen=True)
class JobEvent:
    job_id: UUID
    status: JobStatus
    result: object = None


@dataclass(frozen=True)
class _Job:
    job_id: UUID
    work: Callable[[], object]


def _safe_error(error: Exception) -> JobError:
    if isinstance(error, OSError):
        return JobError("io", "Не удалось прочитать или сохранить файл. Проверьте доступ к нему.")
    if isinstance(error, (AmbiguousParserError, ParserContractError)):
        return JobError("parser", "Не удалось выбрать парсер или проверить его контракт.")
    if isinstance(error, (ValidationError, ValueError, TypeError)):
        return JobError(
            "validation", "Входные данные не соответствуют контракту выбранного сценария."
        )
    return JobError("internal", "Не удалось завершить задание. Результат анализа не получен.")


class JobRunner:
    """Один daemon worker; отмена распространяется лишь на не начавшиеся задания."""

    def __init__(self) -> None:
        self._queue: Queue[_Job | None] = Queue()
        self._events: Queue[JobEvent] = Queue()
        self._lock = Lock()
        self._states: dict[UUID, JobStatus] = {}
        self._callbacks: dict[UUID, Callable[[object], None]] = {}
        self._closed = False
        self._worker = Thread(target=self._run, name="desktop-analysis", daemon=True)
        self._worker.start()

    def submit(self, work: Callable[[], object], callback: Callable[[object], None]) -> UUID:
        """Поставить задание в очередь; callback вызывается только методом poll."""
        with self._lock:
            if self._closed:
                raise RuntimeError("Обработчик заданий уже закрыт.")
            job_id = uuid4()
            self._states[job_id] = JobStatus.PENDING
            self._callbacks[job_id] = callback
            self._queue.put(_Job(job_id, work))
            return job_id

    @property
    def pending_count(self) -> int:
        with self._lock:
            return sum(state == JobStatus.PENDING for state in self._states.values())

    @property
    def running_count(self) -> int:
        with self._lock:
            return sum(state == JobStatus.RUNNING for state in self._states.values())

    def status(self, job_id: UUID) -> JobStatus | None:
        with self._lock:
            return self._states.get(job_id)

    def cancel_pending(self) -> tuple[UUID, ...]:
        """Пометить ожидающие задания; уже выполняющийся анализ продолжится."""
        with self._lock:
            canceled = tuple(
                job_id for job_id, status in self._states.items() if status == JobStatus.PENDING
            )
            for job_id in canceled:
                self._states[job_id] = JobStatus.CANCELED
                self._callbacks.pop(job_id, None)
                self._events.put(JobEvent(job_id, JobStatus.CANCELED))
            return canceled

    def poll(self) -> tuple[JobEvent, ...]:
        """Прочитать события и доставить результаты в вызывающем GUI-потоке."""
        events: list[JobEvent] = []
        while True:
            with self._lock:
                if self._closed:
                    return tuple(events)
                try:
                    event = self._events.get_nowait()
                except Empty:
                    return tuple(events)
                callback = (
                    self._callbacks.pop(event.job_id, None)
                    if event.status in (JobStatus.COMPLETED, JobStatus.FAILED)
                    else None
                )
            events.append(event)
            if callback is not None:
                callback(event.result)

    def shutdown(self) -> None:
        """Закрыть доставку без ожидания и без обещания остановить текущий анализ."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._callbacks.clear()
            for job_id, state in self._states.items():
                if state == JobStatus.PENDING:
                    self._states[job_id] = JobStatus.CANCELED
            while True:
                try:
                    self._events.get_nowait()
                except Empty:
                    break
            self._queue.put(None)

    def _run(self) -> None:
        while (job := self._queue.get()) is not None:
            with self._lock:
                if self._closed or self._states[job.job_id] == JobStatus.CANCELED:
                    continue
                self._states[job.job_id] = JobStatus.RUNNING
                self._events.put(JobEvent(job.job_id, JobStatus.RUNNING))
            try:
                result = job.work()
                status = JobStatus.COMPLETED
            except Exception as error:
                result = _safe_error(error)
                status = JobStatus.FAILED
            with self._lock:
                self._states[job.job_id] = status
                if not self._closed:
                    self._events.put(JobEvent(job.job_id, status, result))
