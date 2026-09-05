from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


class WorkerContractViolation(ValueError):
    pass


@dataclass(frozen=True)
class WorkerContractReport:
    interface_commit: str
    model_count: int
    generated_target_count: int


_SOURCE_REPOSITORY = "file-tunnel/ftnl-interfaces"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MODELS = (
    "WorkerJob",
    "WorkerObjectRef",
    "WorkerObjectTarget",
    "WorkerProductScope",
    "WorkerReceipt",
    "WorkerWorkload",
)
_PROTO_FIELDS: Mapping[str, Mapping[str, tuple[str, int]]] = {
    "WorkerProductScope": {
        "scope_kind": ("string", 1),
        "scope_id": ("string", 2),
    },
    "WorkerWorkload": {
        "item_count": ("uint32", 1),
        "vector_dimensions": ("uint32", 2),
    },
    "WorkerObjectRef": {
        "store_id": ("string", 1),
        "object_id": ("string", 2),
        "version": ("string", 3),
        "content_digest": ("string", 4),
        "expected_bytes": ("uint64", 5),
    },
    "WorkerObjectTarget": {
        "store_id": ("string", 1),
        "object_id": ("string", 2),
        "version": ("string", 3),
    },
    "WorkerJob": {
        "protocol": ("string", 1),
        "job_id": ("string", 2),
        "idempotency_key": ("string", 3),
        "product_scope": ("WorkerProductScope", 4),
        "kind": ("string", 5),
        "workload": ("WorkerWorkload", 6),
        "input": ("WorkerObjectRef", 7),
        "output": ("WorkerObjectTarget", 8),
        "submitted_at_unix": ("uint64", 9),
        "deadline_unix": ("uint64", 10),
        "max_output_bytes": ("uint64", 11),
    },
    "WorkerReceipt": {
        "protocol": ("string", 1),
        "job_id": ("string", 2),
        "status": ("string", 3),
        "code": ("string", 4),
        "output_digest": ("string", 5),
        "bytes_written": ("uint64", 6),
    },
}
_FINAL_SERVER_TARGETS = {
    "gleam/server/src/ftnl_validation_interfaces_server.gleam",
    "golang/server/types.go",
    "rust/server/src/lib.rs",
    "typescript/server/types.ts",
}
_FIELD_PATTERN = re.compile(
    r"(?ms)^\s*(optional\s+)?([A-Za-z][A-Za-z0-9_.]*)\s+"
    r"([a-z][a-z0-9_]*)\s*=\s*([0-9]+)\s*(?:\[(.*?)\])?\s*;"
)
_TYPESPEC_FIELD_PATTERN = re.compile(
    r"^(?P<decorators>(?:@[A-Za-z]+\((?:\"(?:\\.|[^\"])*\"|[0-9]+)\)\s*)*)"
    r"(?P<name>[a-z][a-z0-9_]*)(?P<optional>\?)?:\s*"
    r"(?P<type>[A-Za-z][A-Za-z0-9_]*)\s*;$"
)
_DECORATOR_PATTERN = re.compile(
    r"@(?P<name>[A-Za-z]+)\((?P<value>\"(?:\\.|[^\"])*\"|[0-9]+)\)"
)


def validate_worker_contract(
    *,
    interfaces_root: Path,
    source_lock_path: Path,
    verify_git_revision: bool = False,
    require_protoc: bool = False,
) -> WorkerContractReport:
    root = interfaces_root.resolve()
    source = _validate_source_lock(_read_json(source_lock_path))
    if verify_git_revision:
        actual = _git_revision(root)
        if actual != source["commit"]:
            raise WorkerContractViolation(
                f"interface checkout is {actual}, expected immutable source {source['commit']}"
            )

    schema_path = root / "validation/authorities/server/contracts.json"
    typespec_path = root / "validation/authorities/server/contracts.tsp"
    protobuf_path = root / "protobuf/file_tunnel_worker.proto"
    manifest_path = root / "validation/parity/manifest.v2.json"
    receipt_path = root / "generated/final/parity-receipt.v2.json"

    schema = _read_json(schema_path)
    _validate_schema_envelope(schema)
    json_signature = _json_schema_signature(schema)
    typespec_signature = _typespec_signature(_read_text(typespec_path))
    if json_signature != typespec_signature:
        raise WorkerContractViolation(
            "independent JSON Schema and TypeSpec worker authorities disagree"
        )

    manifest = _read_json(manifest_path)
    _validate_parity_manifest(manifest)
    receipt = _read_json(receipt_path)
    target_count = _validate_parity_receipt(root, receipt, json_signature)
    _validate_runtime_exports(root, manifest)
    _validate_protobuf(
        root=root,
        path=protobuf_path,
        signature=json_signature,
        require_protoc=require_protoc,
    )

    return WorkerContractReport(
        interface_commit=source["commit"],
        model_count=len(json_signature),
        generated_target_count=target_count,
    )


def validate_worker_payload(schema: Mapping[str, Any], payload: Any) -> None:
    alternatives = schema.get("oneOf")
    if not isinstance(alternatives, list) or not alternatives:
        raise WorkerContractViolation("worker schema must declare oneOf payloads")
    accepted = 0
    errors: list[str] = []
    for alternative in alternatives:
        try:
            _validate_schema_node(schema, alternative, payload, path="$")
        except WorkerContractViolation as error:
            errors.append(str(error))
        else:
            accepted += 1
    if accepted != 1:
        detail = "; ".join(errors[:2])
        raise WorkerContractViolation(
            f"worker payload must match exactly one contract (matched {accepted}): {detail}"
        )


def _validate_source_lock(value: Any) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "contract_revision",
        "source",
    }:
        raise WorkerContractViolation("worker source lock fields are not canonical")
    if value["contract_revision"] != "DEN-3384.worker.v1":
        raise WorkerContractViolation("worker contract revision is unsupported")
    source = value["source"]
    if not isinstance(source, Mapping) or set(source) != {"commit", "repository"}:
        raise WorkerContractViolation("worker source fields are not canonical")
    if source["repository"] != _SOURCE_REPOSITORY:
        raise WorkerContractViolation("worker source repository is not canonical")
    if not isinstance(source["commit"], str) or not _SHA.fullmatch(source["commit"]):
        raise WorkerContractViolation("worker source commit must be a full lowercase SHA")
    return source


def _validate_schema_envelope(schema: Any) -> None:
    if not isinstance(schema, Mapping):
        raise WorkerContractViolation("worker JSON Schema must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise WorkerContractViolation("worker schema must use JSON Schema Draft 2020-12")
    if schema.get("contractVersion") != "file-tunnel.worker/v1":
        raise WorkerContractViolation("worker protocol version drifted")
    if schema.get("visibility") != "server":
        raise WorkerContractViolation("worker contracts must remain server-only")
    references = [item.get("$ref") for item in schema.get("oneOf", [])]
    if references != ["#/$defs/WorkerJob", "#/$defs/WorkerReceipt"]:
        raise WorkerContractViolation("worker envelope must accept only jobs or receipts")


def _json_schema_signature(schema: Mapping[str, Any]) -> dict[str, Any]:
    definitions = schema.get("$defs")
    if not isinstance(definitions, Mapping) or set(definitions) != set(_MODELS):
        raise WorkerContractViolation("worker JSON Schema model set drifted")
    signature: dict[str, Any] = {}
    for model_name in _MODELS:
        model = definitions[model_name]
        if (
            not isinstance(model, Mapping)
            or model.get("type") != "object"
            or model.get("additionalProperties") is not False
        ):
            raise WorkerContractViolation(
                f"{model_name} must be a closed JSON object"
            )
        properties = model.get("properties")
        required = model.get("required")
        if not isinstance(properties, Mapping) or not isinstance(required, list):
            raise WorkerContractViolation(f"{model_name} fields are malformed")
        if len(required) != len(set(required)) or not set(required) <= set(properties):
            raise WorkerContractViolation(f"{model_name} required fields are invalid")
        fields: dict[str, Any] = {}
        for field_name, raw in properties.items():
            if not isinstance(raw, Mapping):
                raise WorkerContractViolation(
                    f"{model_name}.{field_name} schema is malformed"
                )
            field: dict[str, Any] = {"required": field_name in required}
            if "$ref" in raw:
                reference = raw["$ref"]
                if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
                    raise WorkerContractViolation(
                        f"{model_name}.{field_name} reference is not local"
                    )
                field.update(type="model", model=reference.rsplit("/", 1)[-1])
            elif raw.get("type") in {"string", "integer"}:
                field["type"] = raw["type"]
            else:
                raise WorkerContractViolation(
                    f"{model_name}.{field_name} has an unsupported type"
                )
            for source_key, target_key in (
                ("minLength", "min_length"),
                ("maxLength", "max_length"),
                ("minimum", "minimum"),
                ("maximum", "maximum"),
                ("pattern", "pattern"),
            ):
                if source_key in raw:
                    field[target_key] = raw[source_key]
            fields[field_name] = field
        signature[model_name] = fields
    return signature


def _typespec_signature(text: str) -> dict[str, Any]:
    signature: dict[str, Any] = {}
    for model_name in _MODELS:
        body = _extract_braced_block(text, rf"model\s+{re.escape(model_name)}")
        fields: dict[str, Any] = {}
        for source_line in body.splitlines():
            line = source_line.strip()
            if not line:
                continue
            match = _TYPESPEC_FIELD_PATTERN.fullmatch(line)
            if match is None:
                raise WorkerContractViolation(
                    f"cannot parse TypeSpec field in {model_name}: {line}"
                )
            field_type = match.group("type")
            field: dict[str, Any] = {"required": match.group("optional") is None}
            if field_type == "string":
                field["type"] = "string"
            elif field_type in {"uint16", "uint32", "uint64"}:
                field["type"] = "integer"
            elif field_type in _MODELS:
                field.update(type="model", model=field_type)
            else:
                raise WorkerContractViolation(
                    f"unsupported TypeSpec type {field_type} in {model_name}"
                )
            for decorator in _DECORATOR_PATTERN.finditer(match.group("decorators")):
                name = decorator.group("name")
                raw_value = decorator.group("value")
                value: Any = (
                    json.loads(raw_value) if raw_value.startswith('"') else int(raw_value)
                )
                key = {
                    "minLength": "min_length",
                    "maxLength": "max_length",
                    "minValue": "minimum",
                    "maxValue": "maximum",
                    "pattern": "pattern",
                }.get(name)
                if key is None:
                    raise WorkerContractViolation(
                        f"unsupported TypeSpec decorator @{name} in {model_name}"
                    )
                field[key] = value
            fields[match.group("name")] = field
        signature[model_name] = fields
    if set(signature) != set(_MODELS):
        raise WorkerContractViolation("worker TypeSpec model set drifted")
    return signature


def _validate_parity_manifest(manifest: Any) -> None:
    if not isinstance(manifest, Mapping):
        raise WorkerContractViolation("parity manifest must be an object")
    if manifest.get("contractVersion") != "ores.validation.v2":
        raise WorkerContractViolation("validation parity contract version drifted")
    if manifest.get("repository") != _SOURCE_REPOSITORY:
        raise WorkerContractViolation("parity manifest repository is not canonical")
    server = (manifest.get("scopes") or {}).get("server")
    if not isinstance(server, Mapping) or set(server.get("models", [])) != set(_MODELS):
        raise WorkerContractViolation("parity manifest server model set drifted")
    if server.get("authorities") != {
        "jsonSchema": "validation/authorities/server/contracts.json",
        "typespec": "validation/authorities/server/contracts.tsp",
    }:
        raise WorkerContractViolation("parity manifest server authorities drifted")
    exports = manifest.get("runtimeExports")
    if not isinstance(exports, Mapping):
        raise WorkerContractViolation("runtime export map is missing")
    if "server" not in exports.get("node", []):
        raise WorkerContractViolation("Node runtime must expose server contracts")
    for runtime in ("browser", "edge"):
        if "server" in exports.get(runtime, []):
            raise WorkerContractViolation(
                f"{runtime} runtime must not expose server contracts"
            )


def _validate_parity_receipt(
    root: Path,
    receipt: Any,
    signature: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> int:
    if not isinstance(receipt, Mapping) or receipt.get("agreement") is not True:
        raise WorkerContractViolation("parity receipt must record authority agreement")
    if receipt.get("generatedOnlyAfterAgreement") is not True:
        raise WorkerContractViolation("generated targets must follow authority agreement")
    if receipt.get("repository") != _SOURCE_REPOSITORY:
        raise WorkerContractViolation("parity receipt repository drifted")
    server = (receipt.get("scopes") or {}).get("server")
    if not isinstance(server, Mapping) or server.get("agreement") is not True:
        raise WorkerContractViolation("server authority agreement is missing")
    if set(server.get("models", [])) != set(_MODELS):
        raise WorkerContractViolation("receipt server model set drifted")
    authorities = server.get("authorities") or {}
    try:
        json_path = authorities["jsonSchema"]["path"]
        json_digest = authorities["jsonSchema"]["semanticDigest"]
        typespec_path = authorities["typespec"]["path"]
        typespec_digest = authorities["typespec"]["semanticDigest"]
    except (KeyError, TypeError) as error:
        raise WorkerContractViolation("server semantic digests are missing") from error
    if (json_path, typespec_path) != (
        "validation/authorities/server/contracts.json",
        "validation/authorities/server/contracts.tsp",
    ):
        raise WorkerContractViolation("server authority receipt paths drifted")
    expected_semantic_digest = _semantic_digest(signature)
    if (
        json_digest != typespec_digest
        or json_digest != expected_semantic_digest
        or not isinstance(json_digest, str)
        or not _DIGEST.fullmatch(json_digest)
    ):
        raise WorkerContractViolation("server semantic authority digests disagree")

    server_targets = set((server.get("targetDigests") or {}).keys())
    if server_targets != _FINAL_SERVER_TARGETS:
        raise WorkerContractViolation("server generated target set drifted")
    all_targets = receipt.get("finalTargetDigests")
    if not isinstance(all_targets, Mapping) or not all_targets:
        raise WorkerContractViolation("final target digests are missing")
    expected_aggregate = hashlib.sha256(_canonical_pretty_json(all_targets).encode()).hexdigest()
    if receipt.get("finalAggregateDigest") != expected_aggregate:
        raise WorkerContractViolation("final generated-target aggregate digest drifted")
    generated_root = (root / "generated/final").resolve()
    for relative, expected in all_targets.items():
        if not isinstance(relative, str) or not isinstance(expected, str) or not _DIGEST.fullmatch(expected):
            raise WorkerContractViolation("final target digest entry is malformed")
        path = (generated_root / relative).resolve()
        if not path.is_relative_to(generated_root):
            raise WorkerContractViolation("final target path escapes generated root")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise WorkerContractViolation(f"generated target digest drifted: {relative}")
    return len(all_targets)


def _semantic_digest(
    signature: Mapping[str, Mapping[str, Mapping[str, Any]]]
) -> str:
    models: dict[str, Any] = {}
    for model_name, fields in signature.items():
        parity_fields: dict[str, Any] = {}
        for field_name, field in fields.items():
            parity_field: dict[str, Any] = {"required": field["required"]}
            if field["type"] == "model":
                parity_field.update(kind="ref", ref=field["model"])
            else:
                parity_field["kind"] = field["type"]
            for source_key, target_key in (
                ("min_length", "minLength"),
                ("max_length", "maxLength"),
                ("minimum", "minimum"),
                ("maximum", "maximum"),
                ("pattern", "pattern"),
            ):
                if source_key in field:
                    parity_field[target_key] = field[source_key]
            parity_fields[field_name] = parity_field
        models[model_name] = {"closed": True, "fields": parity_fields}
    payload = {"models": models}
    return hashlib.sha256(_canonical_pretty_json(payload).encode()).hexdigest()


def _canonical_pretty_json(value: Any) -> str:
    return json.dumps(_deep_sort(value), indent=2, ensure_ascii=False) + "\n"


def _deep_sort(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _deep_sort(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_deep_sort(item) for item in value]
    return value


def _validate_runtime_exports(root: Path, manifest: Mapping[str, Any]) -> None:
    runtime_root = root / "generated/final/typescript/runtime"
    node = _read_text(runtime_root / "node/index.ts")
    for model in _MODELS:
        if model not in node:
            raise WorkerContractViolation(f"Node runtime omits server model {model}")
    if "../../server/types.js" not in node:
        raise WorkerContractViolation("Node runtime server export path drifted")
    for runtime in ("browser", "edge"):
        text = _read_text(runtime_root / f"{runtime}/index.ts")
        if "../../server/" in text or any(model in text for model in _MODELS):
            raise WorkerContractViolation(
                f"{runtime} runtime leaks server-only worker contracts"
            )
    exports = manifest["runtimeExports"]
    if "server" not in exports["node"]:
        raise WorkerContractViolation("Node manifest/runtime export mismatch")


def _validate_protobuf(
    *,
    root: Path,
    path: Path,
    signature: Mapping[str, Mapping[str, Mapping[str, Any]]],
    require_protoc: bool,
) -> None:
    text = _read_text(path)
    if 'syntax = "proto3";' not in text or "package file_tunnel.worker.v1;" not in text:
        raise WorkerContractViolation("worker Protobuf identity drifted")
    for option in (
        "StringRules string_rules = 51001;",
        "IntegerRules integer_rules = 51002;",
        "MessageRules message_rules = 51003;",
    ):
        if option not in text:
            raise WorkerContractViolation(f"worker Protobuf rule option drifted: {option}")

    for model_name, expected_fields in _PROTO_FIELDS.items():
        body = _extract_braced_block(text, rf"message\s+{re.escape(model_name)}")
        actual_fields: dict[str, tuple[str, int, bool, str]] = {}
        for match in _FIELD_PATTERN.finditer(body):
            optional, field_type, field_name, number, options = match.groups()
            actual_fields[field_name] = (
                field_type,
                int(number),
                optional is not None,
                options or "",
            )
        if set(actual_fields) != set(expected_fields):
            raise WorkerContractViolation(f"{model_name} Protobuf field set drifted")
        for field_name, (expected_type, expected_number) in expected_fields.items():
            field_type, number, optional, options = actual_fields[field_name]
            if (field_type, number) != (expected_type, expected_number):
                raise WorkerContractViolation(
                    f"{model_name}.{field_name} Protobuf type or field number drifted"
                )
            field = signature[model_name][field_name]
            if optional == field["required"]:
                raise WorkerContractViolation(
                    f"{model_name}.{field_name} Protobuf optionality drifted"
                )
            if "_" in field_name and not re.search(
                rf'json_name\s*=\s*"{re.escape(field_name)}"', options
            ):
                raise WorkerContractViolation(
                    f"{model_name}.{field_name} must preserve snake_case JSON"
                )
            rules = {
                "string": "string_rules",
                "integer": "integer_rules",
                "model": "message_rules",
            }[field["type"]]
            if rules not in options:
                raise WorkerContractViolation(
                    f"{model_name}.{field_name} has no machine-readable {rules}"
                )
            required_rule = bool(
                re.search(r"required\s*:\s*true", options)
                or re.search(r"\.required\s*=\s*true", options)
            )
            if required_rule != field["required"]:
                raise WorkerContractViolation(
                    f"{model_name}.{field_name} required rule drifted"
                )
            _validate_proto_constraints(model_name, field_name, field, options)

    envelope = _extract_braced_block(text, r"message\s+WorkerEnvelope")
    oneof = _extract_braced_block(envelope, r"oneof\s+payload")
    payloads = {
        match.group(3): (match.group(2), int(match.group(4)))
        for match in _FIELD_PATTERN.finditer(oneof)
    }
    if payloads != {"job": ("WorkerJob", 1), "receipt": ("WorkerReceipt", 2)}:
        raise WorkerContractViolation("worker Protobuf envelope oneof drifted")

    if require_protoc:
        with tempfile.TemporaryDirectory() as temporary:
            descriptor = Path(temporary) / "worker.pb"
            try:
                subprocess.run(
                    [
                        "protoc",
                        "--proto_path",
                        str(root / "protobuf"),
                        "--descriptor_set_out",
                        str(descriptor),
                        "--include_imports",
                        "--fatal_warnings",
                        "file_tunnel_worker.proto",
                    ],
                    check=True,
                    cwd=root / "protobuf",
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as error:
                raise WorkerContractViolation("protoc is required but unavailable") from error
            except subprocess.CalledProcessError as error:
                detail = (error.stderr or error.stdout).strip()
                raise WorkerContractViolation(
                    f"worker Protobuf does not compile: {detail}"
                ) from error
            if not descriptor.is_file() or descriptor.stat().st_size == 0:
                raise WorkerContractViolation("protoc emitted no descriptor set")


def _validate_proto_constraints(
    model_name: str,
    field_name: str,
    field: Mapping[str, Any],
    options: str,
) -> None:
    for key in ("min_length", "max_length", "minimum", "maximum"):
        if key not in field:
            continue
        value = field[key]
        if value == 0 and key == "minimum":
            continue
        if not re.search(rf"{key}\s*[:=]\s*{value}(?:\s|$)", options):
            raise WorkerContractViolation(
                f"{model_name}.{field_name} Protobuf {key} rule drifted"
            )
    if "pattern" in field:
        match = re.search(r'pattern\s*[:=]\s*("(?:\\.|[^\"])*")', options)
        if match is None:
            raise WorkerContractViolation(
                f"{model_name}.{field_name} Protobuf pattern rule is missing"
            )
        actual = _normalize_pattern(json.loads(match.group(1)))
        expected = _normalize_pattern(str(field["pattern"]))
        if actual != expected:
            raise WorkerContractViolation(
                f"{model_name}.{field_name} Protobuf pattern rule drifted"
            )


def _validate_schema_node(
    schema: Mapping[str, Any], node: Mapping[str, Any], value: Any, *, path: str
) -> None:
    if "$ref" in node:
        reference = node["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
            raise WorkerContractViolation(f"{path} has an unsupported reference")
        target = schema["$defs"][reference.rsplit("/", 1)[-1]]
        _validate_schema_node(schema, target, value, path=path)
        return
    expected_type = node.get("type")
    if expected_type == "object":
        if not isinstance(value, Mapping):
            raise WorkerContractViolation(f"{path} must be an object")
        properties = node.get("properties") or {}
        required = set(node.get("required") or [])
        missing = required - set(value)
        if missing:
            raise WorkerContractViolation(f"{path} is missing required fields")
        if node.get("additionalProperties") is False and not set(value) <= set(properties):
            raise WorkerContractViolation(f"{path} contains unknown fields")
        for key, item in value.items():
            _validate_schema_node(schema, properties[key], item, path=f"{path}.{key}")
        return
    if expected_type == "string":
        if not isinstance(value, str):
            raise WorkerContractViolation(f"{path} must be a string")
        if len(value) < node.get("minLength", 0):
            raise WorkerContractViolation(f"{path} is shorter than its minimum")
        if "maxLength" in node and len(value) > node["maxLength"]:
            raise WorkerContractViolation(f"{path} exceeds its maximum length")
        if "pattern" in node and re.search(node["pattern"], value) is None:
            raise WorkerContractViolation(f"{path} does not match its pattern")
        return
    if expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise WorkerContractViolation(f"{path} must be an integer")
        if value < node.get("minimum", value):
            raise WorkerContractViolation(f"{path} is below its minimum")
        if "maximum" in node and value > node["maximum"]:
            raise WorkerContractViolation(f"{path} exceeds its maximum")
        return
    raise WorkerContractViolation(f"{path} uses an unsupported schema type")


def _extract_braced_block(text: str, declaration_pattern: str) -> str:
    declaration = re.search(declaration_pattern + r"\s*\{", text)
    if declaration is None:
        raise WorkerContractViolation(f"missing declaration: {declaration_pattern}")
    opening = text.find("{", declaration.start())
    depth = 0
    in_string = False
    escaped = False
    for index in range(opening, len(text)):
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1 : index]
    raise WorkerContractViolation(f"unclosed declaration: {declaration_pattern}")


def _normalize_pattern(value: str) -> str:
    return value.replace(r"\x3a", ":")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WorkerContractViolation(f"cannot read canonical JSON: {path}") from error


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise WorkerContractViolation(f"cannot read contract source: {path}") from error


def _git_revision(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise WorkerContractViolation("cannot resolve interface Git revision") from error
    return result.stdout.strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify File Tunnel worker contracts across independent authorities."
    )
    parser.add_argument("--interfaces", required=True, type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--verify-git-revision", action="store_true")
    parser.add_argument("--require-protoc", action="store_true")
    args = parser.parse_args(argv)
    report = validate_worker_contract(
        interfaces_root=args.interfaces,
        source_lock_path=args.source_lock,
        verify_git_revision=args.verify_git_revision,
        require_protoc=args.require_protoc,
    )
    print(
        f"validated {report.model_count} worker models and "
        f"{report.generated_target_count} generated targets at "
        f"interface {report.interface_commit}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
