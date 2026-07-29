"""Mutable live state for the adaptive red-team TUI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock

from cot_redteam.eval.events import RunEvent, RunEventKind


@dataclass
class ActivityLine:
    timestamp: datetime
    kind: str
    message: str
    ok: bool | None = None
    model: str | None = None


@dataclass
class ModelBoardRow:
    model: str
    status: str = "pending"
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    last_payload: str = "-"
    tokens_in: int = 0
    tokens_out: int = 0
    last_message: str = ""


@dataclass
class TuiState:
    title: str = "CoT Red Team Agent"
    status: str = "idle"
    run_id: str = "-"
    model: str = "-"
    attack_id: str = "-"
    sample_id: str = "-"
    payload_id: str = "-"
    attempt: int = 0
    attempts_total: int = 0
    effort: str = "adaptive"
    sandbox: str = "local-eval"
    max_payloads: int = 12
    stop_on_success: bool = True
    current_activity: str = "waiting — type /help"
    last_output: str = "No output yet."
    last_success: str = "No successful disclosure yet."
    command_hint: str = "/help · /models · /payloads N · /run · /stop · /quit"
    tokens_input: int = 0
    tokens_output: int = 0
    successes: int = 0
    failures: int = 0
    items_done: int = 0
    items_planned: int = 0
    started_at: datetime | None = None
    finished: bool = False
    configured_models: list[str] = field(default_factory=list)
    model_board: dict[str, ModelBoardRow] = field(default_factory=dict)
    activity: list[ActivityLine] = field(default_factory=list)
    help_text: str = ""
    _lock: Lock = field(default_factory=Lock, repr=False)

    def elapsed_seconds(self) -> float:
        if self.started_at is None:
            return 0.0
        end = datetime.now(timezone.utc)
        return max(0.0, (end - self.started_at).total_seconds())

    def ensure_models(self, models: list[str]) -> None:
        with self._lock:
            self.configured_models = list(models)
            for model in models:
                if model not in self.model_board:
                    self.model_board[model] = ModelBoardRow(model=model)

    def reset_for_run(self) -> None:
        with self._lock:
            self.status = "starting"
            self.finished = False
            self.successes = 0
            self.failures = 0
            self.items_done = 0
            self.items_planned = 0
            self.tokens_input = 0
            self.tokens_output = 0
            self.attempt = 0
            self.attempts_total = 0
            self.payload_id = "-"
            self.last_output = "Run starting…"
            self.started_at = datetime.now(timezone.utc)
            for row in self.model_board.values():
                row.status = "pending"
                row.attempts = 0
                row.successes = 0
                row.failures = 0
                row.last_payload = "-"
                row.tokens_in = 0
                row.tokens_out = 0
                row.last_message = ""

    def push_activity(
        self,
        kind: str,
        message: str,
        *,
        ok: bool | None = None,
        model: str | None = None,
        ts: datetime | None = None,
    ) -> None:
        line = ActivityLine(
            timestamp=ts or datetime.now(timezone.utc),
            kind=kind,
            message=message,
            ok=ok,
            model=model,
        )
        with self._lock:
            self.activity.append(line)
            if len(self.activity) > 60:
                self.activity = self.activity[-60:]

    def _board(self, model: str | None) -> ModelBoardRow | None:
        if not model:
            return None
        if model not in self.model_board:
            self.model_board[model] = ModelBoardRow(model=model)
        return self.model_board[model]

    def apply_event(self, event: RunEvent) -> None:
        with self._lock:
            if event.run_id:
                self.run_id = event.run_id
            if event.model:
                self.model = event.model
            if event.attack_id:
                self.attack_id = event.attack_id
            if event.sample_id:
                self.sample_id = event.sample_id
            if event.payload_id:
                self.payload_id = event.payload_id
            if event.attempt is not None:
                self.attempt = event.attempt
            if event.attempts_total is not None:
                self.attempts_total = event.attempts_total
            if event.tokens_input:
                self.tokens_input += event.tokens_input
            if event.tokens_output:
                self.tokens_output += event.tokens_output

            board = self._board(event.model)
            if board is not None:
                if event.payload_id:
                    board.last_payload = event.payload_id
                if event.tokens_input:
                    board.tokens_in += event.tokens_input
                if event.tokens_output:
                    board.tokens_out += event.tokens_output

            if event.kind is RunEventKind.RUN_STARTED:
                self.status = "running"
                self.started_at = event.timestamp
                self.finished = False
                self.items_planned = int(event.detail.get("planned") or 0)
                self.current_activity = event.message or "run started"
                self.activity.append(
                    ActivityLine(event.timestamp, "run", event.message or "started", True)
                )
            elif event.kind is RunEventKind.ITEM_STARTED:
                self.status = "running"
                self.current_activity = event.message or "item started"
                if board is not None:
                    board.status = "running"
                    board.last_message = event.message or "started"
                self.activity.append(
                    ActivityLine(
                        event.timestamp,
                        "item",
                        event.message or "item",
                        None,
                        event.model,
                    )
                )
            elif event.kind is RunEventKind.ATTEMPT_STARTED:
                self.status = "probing"
                self.current_activity = event.message or "attempt started"
                if board is not None:
                    board.status = "probing"
                    board.attempts += 1
                    board.last_message = event.message or "probing"
                self.activity.append(
                    ActivityLine(
                        event.timestamp,
                        "payload",
                        event.message or f"try {event.payload_id}",
                        None,
                        event.model,
                    )
                )
            elif event.kind is RunEventKind.ATTEMPT_FINISHED:
                ok = bool(event.success)
                if ok:
                    self.successes += 1
                    preview = str(event.detail.get("response_preview") or "")
                    self.last_output = preview or event.message
                    self.last_success = (
                        f"SUCCESS payload={event.payload_id} model={event.model}\n"
                        f"{preview or event.message}"
                    )
                    self.current_activity = f"real disclosure via {event.payload_id}"
                    if board is not None:
                        board.successes += 1
                        board.status = "success"
                        board.last_message = "disclosure"
                else:
                    self.failures += 1
                    refusal = event.detail.get("refusal_analysis_with_canary_quote")
                    note = " (refusal quote ignored)" if refusal else ""
                    self.current_activity = f"payload failed{note}: {event.payload_id}"
                    preview = str(event.detail.get("response_preview") or event.message)
                    self.last_output = preview
                    if board is not None:
                        board.failures += 1
                        board.status = "probing"
                        board.last_message = "fail"
                self.activity.append(
                    ActivityLine(
                        event.timestamp,
                        "result",
                        event.message or ("success" if ok else "fail"),
                        ok,
                        event.model,
                    )
                )
            elif event.kind is RunEventKind.ITEM_FINISHED:
                self.items_done += 1
                self.current_activity = event.message or event.status or "item finished"
                if board is not None:
                    if event.status == "succeeded" and event.success:
                        board.status = "success"
                    elif event.status == "succeeded":
                        board.status = "defended"
                    elif event.status in {"provider_error", "attack_error", "monitor_error"}:
                        board.status = "error"
                    elif event.status == "cancelled":
                        board.status = "cancelled"
                    else:
                        board.status = event.status or "done"
                    board.last_message = event.message or board.status
                self.activity.append(
                    ActivityLine(
                        event.timestamp,
                        "item",
                        event.message or event.status or "done",
                        event.success,
                        event.model,
                    )
                )
            elif event.kind is RunEventKind.RUN_FINISHED:
                self.status = event.status or "completed"
                self.finished = True
                self.current_activity = event.message or "run finished"
                self.activity.append(
                    ActivityLine(event.timestamp, "run", event.message or "finished", True)
                )
            elif event.kind is RunEventKind.ACTIVITY:
                self.current_activity = event.message
                self.activity.append(
                    ActivityLine(event.timestamp, "activity", event.message, None, event.model)
                )

            if len(self.activity) > 60:
                self.activity = self.activity[-60:]
