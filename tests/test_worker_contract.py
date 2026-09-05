from __future__ import annotations

import copy
import json
import unittest

from deep_tests.worker_contract import (
    WorkerContractViolation,
    _json_schema_signature,
    _semantic_digest,
    _typespec_signature,
    _validate_source_lock,
    validate_worker_payload,
)


class WorkerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = self._authority_schema()
        self.job = {
            "protocol": "file-tunnel.worker/v1",
            "job_id": "job-1",
            "idempotency_key": "idem-1",
            "product_scope": {
                "scope_kind": "organization",
                "scope_id": "organization-1",
            },
            "kind": "embedding_batch",
            "workload": {"item_count": 16, "vector_dimensions": 1536},
            "input": {
                "store_id": "canonical-store",
                "object_id": "object-1",
                "version": "v1",
                "content_digest": "sha256:" + "a" * 64,
                "expected_bytes": 4096,
            },
            "output": {
                "store_id": "derived-store",
                "object_id": "embedding-1",
                "version": "v1",
            },
            "submitted_at_unix": 1_788_600_000,
            "deadline_unix": 1_788_600_300,
            "max_output_bytes": 8_388_608,
        }

    def test_payload_validator_accepts_bounded_job_and_receipt(self) -> None:
        validate_worker_payload(self.schema, self.job)
        validate_worker_payload(
            self.schema,
            {
                "protocol": "file-tunnel.worker/v1",
                "job_id": "job-1",
                "status": "completed",
                "code": "ok",
                "output_digest": "sha256:" + "b" * 64,
                "bytes_written": 1024,
            },
        )

    def test_payload_validator_rejects_remote_inline_and_path_shaped_handles(self) -> None:
        values = (
            "https://objects.invalid/customer/object",
            "data:application/octet-stream;base64,AAAA",
            "../customer/object",
            "/absolute/customer/object",
        )
        for value in values:
            with self.subTest(value=value):
                changed = copy.deepcopy(self.job)
                changed["input"]["object_id"] = value
                with self.assertRaises(WorkerContractViolation):
                    validate_worker_payload(self.schema, changed)

    def test_payload_validator_rejects_unknown_fields_and_kinds(self) -> None:
        unknown_field = copy.deepcopy(self.job)
        unknown_field["bearer_token"] = "not-a-token"
        unknown_kind = copy.deepcopy(self.job)
        unknown_kind["kind"] = "execute_arbitrary_command"
        for payload in (unknown_field, unknown_kind):
            with self.subTest(payload=payload), self.assertRaises(
                WorkerContractViolation
            ):
                validate_worker_payload(self.schema, payload)

    def test_payload_validator_enforces_workload_digest_and_size_bounds(self) -> None:
        mutations = (
            ("workload", "item_count", 100_001),
            ("workload", "vector_dimensions", 4097),
            ("input", "expected_bytes", 2_147_483_649),
            ("input", "content_digest", "sha256:" + "A" * 64),
            (None, "max_output_bytes", 536_870_913),
            (None, "submitted_at_unix", True),
        )
        for parent, key, value in mutations:
            with self.subTest(parent=parent, key=key, value=value):
                changed = copy.deepcopy(self.job)
                target = changed if parent is None else changed[parent]
                target[key] = value
                with self.assertRaises(WorkerContractViolation):
                    validate_worker_payload(self.schema, changed)

    def test_payload_validator_requires_exactly_one_envelope_variant(self) -> None:
        missing = copy.deepcopy(self.job)
        del missing["output"]
        with self.assertRaises(WorkerContractViolation):
            validate_worker_payload(self.schema, missing)
        with self.assertRaises(WorkerContractViolation):
            validate_worker_payload(self.schema, {})

    def test_source_lock_requires_exact_repository_and_immutable_commit(self) -> None:
        source_lock = {
            "contract_revision": "DEN-3384.worker.v1",
            "source": {
                "repository": "file-tunnel/ftnl-interfaces",
                "commit": "a" * 40,
            },
        }
        self.assertEqual(_validate_source_lock(source_lock), source_lock["source"])
        mutations = []
        short_sha = copy.deepcopy(source_lock)
        short_sha["source"]["commit"] = "main"
        mutations.append(short_sha)
        wrong_repository = copy.deepcopy(source_lock)
        wrong_repository["source"]["repository"] = "someone/fork"
        mutations.append(wrong_repository)
        unknown_field = copy.deepcopy(source_lock)
        unknown_field["source"]["ref"] = "main"
        mutations.append(unknown_field)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                WorkerContractViolation
            ):
                _validate_source_lock(mutation)

    def test_authority_signatures_match_and_detect_constraint_drift(self) -> None:
        json_signature = _json_schema_signature(self.schema)
        typespec = self._typespec_authority()
        self.assertEqual(json_signature, _typespec_signature(typespec))
        self.assertEqual(
            _semantic_digest(json_signature),
            "225bed75636329435b23f9dd266598961493f6268ee088313a68a75ef4ebab7b",
        )
        drifted = typespec.replace("@maxValue(4096)", "@maxValue(4097)")
        drifted_signature = _typespec_signature(drifted)
        self.assertNotEqual(json_signature, drifted_signature)
        self.assertNotEqual(
            _semantic_digest(json_signature), _semantic_digest(drifted_signature)
        )

    @staticmethod
    def _authority_schema() -> dict:
        identifier = {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
            "pattern": "^[A-Za-z0-9_.-]+$",
        }
        digest = {"type": "string", "pattern": r"^sha256\x3a[0-9a-f]{64}$"}
        definitions = {
            "WorkerProductScope": {
                "type": "object",
                "additionalProperties": False,
                "required": ["scope_kind", "scope_id"],
                "properties": {
                    "scope_kind": {
                        "type": "string",
                        "pattern": "^individual$|^organization$",
                    },
                    "scope_id": copy.deepcopy(identifier),
                },
            },
            "WorkerWorkload": {
                "type": "object",
                "additionalProperties": False,
                "required": ["item_count"],
                "properties": {
                    "item_count": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100_000,
                    },
                    "vector_dimensions": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 4096,
                    },
                },
            },
            "WorkerObjectRef": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "store_id",
                    "object_id",
                    "version",
                    "content_digest",
                    "expected_bytes",
                ],
                "properties": {
                    "store_id": copy.deepcopy(identifier),
                    "object_id": copy.deepcopy(identifier),
                    "version": copy.deepcopy(identifier),
                    "content_digest": copy.deepcopy(digest),
                    "expected_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 2_147_483_648,
                    },
                },
            },
            "WorkerObjectTarget": {
                "type": "object",
                "additionalProperties": False,
                "required": ["store_id", "object_id", "version"],
                "properties": {
                    "store_id": copy.deepcopy(identifier),
                    "object_id": copy.deepcopy(identifier),
                    "version": copy.deepcopy(identifier),
                },
            },
            "WorkerJob": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "protocol",
                    "job_id",
                    "idempotency_key",
                    "product_scope",
                    "kind",
                    "workload",
                    "input",
                    "output",
                    "submitted_at_unix",
                    "deadline_unix",
                    "max_output_bytes",
                ],
                "properties": {
                    "protocol": {
                        "type": "string",
                        "pattern": r"^file-tunnel\.worker/v1$",
                    },
                    "job_id": copy.deepcopy(identifier),
                    "idempotency_key": copy.deepcopy(identifier),
                    "product_scope": {"$ref": "#/$defs/WorkerProductScope"},
                    "kind": {
                        "type": "string",
                        "pattern": "^file_metadata$|^image_metadata$|^image_thumbnail$|^image_transcode$|^embedding_batch$|^regression_batch$|^correlation_discovery$",
                    },
                    "workload": {"$ref": "#/$defs/WorkerWorkload"},
                    "input": {"$ref": "#/$defs/WorkerObjectRef"},
                    "output": {"$ref": "#/$defs/WorkerObjectTarget"},
                    "submitted_at_unix": {"type": "integer", "minimum": 0},
                    "deadline_unix": {"type": "integer", "minimum": 1},
                    "max_output_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 536_870_912,
                    },
                },
            },
            "WorkerReceipt": {
                "type": "object",
                "additionalProperties": False,
                "required": ["protocol", "job_id", "status", "code"],
                "properties": {
                    "protocol": {
                        "type": "string",
                        "pattern": r"^file-tunnel\.worker/v1$",
                    },
                    "job_id": copy.deepcopy(identifier),
                    "status": {
                        "type": "string",
                        "pattern": "^completed$|^retryable_failure$|^terminal_failure$",
                    },
                    "code": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": "^[a-z][a-z0-9_]*$",
                    },
                    "output_digest": copy.deepcopy(digest),
                    "bytes_written": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 536_870_912,
                    },
                },
            },
        }
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "contractVersion": "file-tunnel.worker/v1",
            "visibility": "server",
            "oneOf": [
                {"$ref": "#/$defs/WorkerJob"},
                {"$ref": "#/$defs/WorkerReceipt"},
            ],
            "$defs": definitions,
        }

    @staticmethod
    def _typespec_authority() -> str:
        return r'''
model WorkerProductScope {
  @pattern("^individual$|^organization$") scope_kind: string;
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") scope_id: string;
}
model WorkerWorkload {
  @minValue(1) @maxValue(100000) item_count: uint32;
  @minValue(1) @maxValue(4096) vector_dimensions?: uint16;
}
model WorkerObjectRef {
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") store_id: string;
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") object_id: string;
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") version: string;
  @pattern("^sha256\\x3a[0-9a-f]{64}$") content_digest: string;
  @minValue(1) @maxValue(2147483648) expected_bytes: uint64;
}
model WorkerObjectTarget {
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") store_id: string;
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") object_id: string;
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") version: string;
}
model WorkerJob {
  @pattern("^file-tunnel\\.worker/v1$") protocol: string;
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") job_id: string;
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") idempotency_key: string;
  product_scope: WorkerProductScope;
  @pattern("^file_metadata$|^image_metadata$|^image_thumbnail$|^image_transcode$|^embedding_batch$|^regression_batch$|^correlation_discovery$") kind: string;
  workload: WorkerWorkload;
  input: WorkerObjectRef;
  output: WorkerObjectTarget;
  @minValue(0) submitted_at_unix: uint64;
  @minValue(1) deadline_unix: uint64;
  @minValue(1) @maxValue(536870912) max_output_bytes: uint64;
}
model WorkerReceipt {
  @pattern("^file-tunnel\\.worker/v1$") protocol: string;
  @minLength(1) @maxLength(256) @pattern("^[A-Za-z0-9_.-]+$") job_id: string;
  @pattern("^completed$|^retryable_failure$|^terminal_failure$") status: string;
  @minLength(1) @maxLength(128) @pattern("^[a-z][a-z0-9_]*$") code: string;
  @pattern("^sha256\\x3a[0-9a-f]{64}$") output_digest?: string;
  @minValue(1) @maxValue(536870912) bytes_written?: uint64;
}
'''


if __name__ == "__main__":
    unittest.main()
