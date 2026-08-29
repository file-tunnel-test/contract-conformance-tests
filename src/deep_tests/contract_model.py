from __future__ import annotations

import datetime
import hashlib
import json
import random
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


class IdempotencyConflict(ValueError):
    pass


class ContractViolation(ValueError):
    pass


@dataclass(frozen=True)
class Command:
    kind: str
    entity_id: str
    value: str | None
    idempotency_key: str

    def fingerprint(self) -> str:
        body = json.dumps(
            {"entity_id": self.entity_id, "kind": self.kind, "value": self.value},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Outcome:
    revision: int
    entity_id: str
    value: str | None
    deleted: bool


class ReferenceStore:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}
        self._tombstones: set[str] = set()
        self._revision = 0
        self._dedupe: dict[str, tuple[str, Outcome]] = {}
        self._history: list[Outcome] = []

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def history(self) -> tuple[Outcome, ...]:
        return tuple(self._history)

    def apply(self, command: Command) -> Outcome:
        fingerprint = command.fingerprint()
        prior = self._dedupe.get(command.idempotency_key)
        if prior is not None:
            prior_fingerprint, prior_outcome = prior
            if prior_fingerprint != fingerprint:
                raise IdempotencyConflict("idempotency key was reused for different intent")
            return prior_outcome

        if command.kind == "create":
            if command.value is None or command.entity_id in self._values:
                raise ValueError("create requires a value and a missing entity")
            self._values[command.entity_id] = command.value
            self._tombstones.discard(command.entity_id)
            deleted = False
        elif command.kind == "update":
            if command.value is None or command.entity_id not in self._values:
                raise ValueError("update requires an existing entity and a value")
            self._values[command.entity_id] = command.value
            deleted = False
        elif command.kind == "delete":
            if command.entity_id not in self._values:
                raise ValueError("delete requires an existing entity")
            del self._values[command.entity_id]
            self._tombstones.add(command.entity_id)
            deleted = True
        else:
            raise ValueError(f"unknown command kind: {command.kind}")

        self._revision += 1
        outcome = Outcome(
            revision=self._revision,
            entity_id=command.entity_id,
            value=None if deleted else self._values[command.entity_id],
            deleted=deleted,
        )
        self._dedupe[command.idempotency_key] = (fingerprint, outcome)
        self._history.append(outcome)
        return outcome

    def snapshot(self) -> str:
        return json.dumps(
            {
                "revision": self._revision,
                "tombstones": sorted(self._tombstones),
                "values": dict(sorted(self._values.items())),
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def generate_valid_trace(seed: int, steps: int = 250) -> tuple[Command, ...]:
    randomizer = random.Random(seed)
    live: set[str] = set()
    next_id = 0
    commands: list[Command] = []
    for index in range(steps):
        decision = randomizer.random()
        if not live or decision < 0.36:
            entity_id = f"entity-{seed}-{next_id}"
            next_id += 1
            live.add(entity_id)
            kind = "create"
            value = f"value-{randomizer.randrange(1_000_000)}"
        elif decision < 0.79:
            entity_id = randomizer.choice(sorted(live))
            kind = "update"
            value = f"value-{randomizer.randrange(1_000_000)}"
        else:
            entity_id = randomizer.choice(sorted(live))
            live.remove(entity_id)
            kind = "delete"
            value = None
        commands.append(
            Command(
                kind=kind,
                entity_id=entity_id,
                value=value,
                idempotency_key=f"seed-{seed}-step-{index}",
            )
        )
    return tuple(commands)


def replay(commands: Iterable[Command], duplicate_every: int = 0) -> ReferenceStore:
    store = ReferenceStore()
    for index, command in enumerate(commands):
        first = store.apply(command)
        if duplicate_every and index % duplicate_every == 0:
            assert store.apply(command) == first
    return store


_CONTRACT_NAMES = frozenset({"tunnel", "events", "proximity", "desktop_companion"})
_IMPLEMENTATIONS = frozenset({"rust_desktop", "flutter_desktop"})
_ISSUE_URL = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[0-9]+$"
)


def validate_desktop_parity_record(
    record: Mapping[str, Any], *, today: datetime.date
) -> None:
    if frozenset(record) != {
        "contract_version",
        "change_id",
        "changed_contracts",
        "implementations",
    }:
        raise ContractViolation("desktop parity record fields are not canonical")
    if record["contract_version"] != 1:
        raise ContractViolation("desktop parity contract version is unsupported")
    change_id = record["change_id"]
    if not isinstance(change_id, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", change_id):
        raise ContractViolation("desktop parity change id is invalid")

    changed = record["changed_contracts"]
    if (
        not isinstance(changed, list)
        or not changed
        or len(changed) != len(set(changed))
        or not set(changed) <= _CONTRACT_NAMES
    ):
        raise ContractViolation("changed contracts must be unique canonical names")

    implementations = record["implementations"]
    if not isinstance(implementations, Mapping) or frozenset(implementations) != _IMPLEMENTATIONS:
        raise ContractViolation("both Rust and Flutter impacts are required")
    for implementation, impact in implementations.items():
        _validate_implementation_impact(implementation, impact, today=today)


def _validate_implementation_impact(
    implementation: str, impact: Any, *, today: datetime.date
) -> None:
    if not isinstance(impact, Mapping):
        raise ContractViolation(f"{implementation} impact must be an object")
    status = impact.get("status")
    repository = impact.get("repository")
    if not isinstance(repository, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]*/[A-Za-z0-9._-]{1,180}", repository
    ):
        raise ContractViolation(f"{implementation} repository is invalid")

    if status == "implemented":
        if frozenset(impact) != {"repository", "status", "evidence"}:
            raise ContractViolation(f"{implementation} implemented fields are not canonical")
        evidence = impact["evidence"]
        if not isinstance(evidence, list) or not evidence or len(evidence) != len(set(evidence)):
            raise ContractViolation(f"{implementation} needs unique implementation evidence")
        return

    required = {"repository", "status", "rationale", "review_expires_on"}
    if status == "blocked":
        required.add("follow_up_issue")
    elif status != "not_affected":
        raise ContractViolation(f"{implementation} status is invalid")
    if frozenset(impact) != required:
        raise ContractViolation(f"{implementation} deferred fields are not canonical")
    if not isinstance(impact["rationale"], str) or len(impact["rationale"]) < 20:
        raise ContractViolation(f"{implementation} rationale is too short")
    try:
        review_expires_on = datetime.date.fromisoformat(impact["review_expires_on"])
    except (TypeError, ValueError) as error:
        raise ContractViolation(f"{implementation} review expiry is invalid") from error
    if review_expires_on < today:
        raise ContractViolation(f"{implementation} deferred review has expired")
    if status == "blocked" and not _ISSUE_URL.fullmatch(impact["follow_up_issue"]):
        raise ContractViolation(f"{implementation} blocker needs a GitHub issue")
