"""Проверки доставки фоновых результатов без Tkinter и исходных конфигураций."""

from threading import Event, get_ident
from time import monotonic, sleep
from uuid import UUID

import pytest
from pydantic import BaseModel, ValidationError

from firewall_compliance.interfaces.desktop.jobs import JobError, JobRunner, JobStatus
from firewall_compliance.parsers.registry import AmbiguousParserError, ParserContractError


def _wait_status(runner: JobRunner, job_id: UUID, expected: JobStatus) -> None:
    deadline = monotonic() + 3
    while runner.status(job_id) != expected:
        assert monotonic() < deadline, f"Задание не достигло {expected}"
        sleep(0.005)


def test_callbacks_are_delivered_on_poll_thread_and_workers_are_serial() -> None:
    runner = JobRunner()
    release = Event()
    started = Event()
    worker_threads: list[int] = []
    callback_threads: list[int] = []
    results: list[object] = []

    def first() -> object:
        worker_threads.append(get_ident())
        started.set()
        assert release.wait(3)
        return "first"

    def second() -> object:
        worker_threads.append(get_ident())
        return "second"

    def callback(result: object) -> None:
        callback_threads.append(get_ident())
        results.append(result)

    try:
        first_id = runner.submit(first, callback)
        assert started.wait(3)
        second_id = runner.submit(second, callback)
        assert runner.running_count == 1
        assert runner.pending_count == 1
        assert results == []
        release.set()
        _wait_status(runner, second_id, JobStatus.COMPLETED)
        assert results == []
        events = runner.poll()
        assert results == ["first", "second"]
        assert callback_threads == [get_ident(), get_ident()]
        assert worker_threads[0] == worker_threads[1] != get_ident()
        assert [event.job_id for event in events if event.status == JobStatus.COMPLETED] == [
            first_id,
            second_id,
        ]
        assert runner.poll() == ()
        assert runner.pending_count == runner.running_count == 0
    finally:
        release.set()
        runner.shutdown()


def test_cancel_pending_preserves_current_work_and_runner_can_continue() -> None:
    runner = JobRunner()
    started = Event()
    release = Event()
    delivered: list[object] = []
    queued_calls: list[str] = []

    def work() -> object:
        started.set()
        assert release.wait(3)
        return "running result"

    def queued() -> object:
        queued_calls.append("unexpected")
        return None

    try:
        current_id = runner.submit(work, delivered.append)
        assert started.wait(3)
        canceled_id = runner.submit(queued, delivered.append)
        assert runner.cancel_pending() == (canceled_id,)
        assert runner.status(current_id) == JobStatus.RUNNING
        assert runner.status(canceled_id) == JobStatus.CANCELED
        assert runner.cancel_pending() == ()
        release.set()
        _wait_status(runner, current_id, JobStatus.COMPLETED)
        runner.poll()
        assert delivered == ["running result"]
        assert queued_calls == []
        next_id = runner.submit(lambda: "next", delivered.append)
        _wait_status(runner, next_id, JobStatus.COMPLETED)
        runner.poll()
        assert delivered == ["running result", "next"]
    finally:
        release.set()
        runner.shutdown()


def test_shutdown_suppresses_late_and_already_queued_callbacks() -> None:
    runner = JobRunner()
    started = Event()
    release = Event()
    delivered: list[object] = []

    def work() -> object:
        started.set()
        assert release.wait(3)
        return "late"

    done_id = runner.submit(lambda: "already done", delivered.append)
    _wait_status(runner, done_id, JobStatus.COMPLETED)
    running_id = runner.submit(work, delivered.append)
    assert started.wait(3)
    pending_id = runner.submit(lambda: "never run", delivered.append)
    runner.shutdown()
    runner.shutdown()
    assert runner.status(pending_id) == JobStatus.CANCELED
    assert runner.status(running_id) == JobStatus.RUNNING
    release.set()
    _wait_status(runner, running_id, JobStatus.COMPLETED)
    assert runner.poll() == ()
    assert delivered == []
    with pytest.raises(RuntimeError, match="закрыт"):
        runner.submit(lambda: None, delivered.append)


def test_callback_may_close_runner_without_delivering_other_results() -> None:
    runner = JobRunner()
    delivered: list[object] = []

    def close(result: object) -> None:
        delivered.append(result)
        runner.shutdown()

    runner.submit(lambda: "first", close)
    second_id = runner.submit(lambda: "second", delivered.append)
    _wait_status(runner, second_id, JobStatus.COMPLETED)
    runner.poll()
    assert delivered == ["first"]
    assert runner.poll() == ()


@pytest.mark.parametrize(
    ("error_type", "category"),
    [
        (OSError, "io"),
        (PermissionError, "io"),
        (ValueError, "validation"),
        (TypeError, "validation"),
        (AmbiguousParserError, "parser"),
        (ParserContractError, "parser"),
        (RuntimeError, "internal"),
    ],
)
def test_exceptions_never_deliver_sensitive_exception_text(
    error_type: type[Exception], category: str
) -> None:
    runner = JobRunner()
    results: list[object] = []

    def work() -> object:
        raise error_type("secret-password raw-configuration /customer/path")

    try:
        job_id = runner.submit(work, results.append)
        _wait_status(runner, job_id, JobStatus.FAILED)
        runner.poll()
        assert len(results) == 1
        error = results[0]
        assert isinstance(error, JobError)
        assert error.category == category
        assert error.message
        assert "secret-password" not in repr(error)
        assert "raw-configuration" not in repr(error)
        assert "/customer/path" not in repr(error)
    finally:
        runner.shutdown()


def test_validation_error_input_is_not_exposed() -> None:
    class Input(BaseModel):
        number: int

    runner = JobRunner()
    results: list[object] = []

    def work() -> object:
        try:
            Input.model_validate({"number": "secret-password"})
        except ValidationError:
            raise
        return None

    try:
        job_id = runner.submit(work, results.append)
        _wait_status(runner, job_id, JobStatus.FAILED)
        runner.poll()
        assert results == [
            JobError("validation", "Входные данные не соответствуют контракту выбранного сценария.")
        ]
    finally:
        runner.shutdown()
