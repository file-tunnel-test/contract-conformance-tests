from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


class DesktopContractViolation(ValueError):
    pass


@dataclass(frozen=True)
class DesktopContractReport:
    contract_revision: str
    interface_commit: str
    feature_count: int
    assembled_manifest: Mapping[str, Any]


_SHA256 = re.compile(r"^[0-9a-f]{40}$")
_DEN_ISSUE = re.compile(r"^DEN-[1-9][0-9]*$")
_REVISION = re.compile(r"^DEN-[1-9][0-9]*\.v[1-9][0-9]*$")
_EVIDENCE = re.compile(r"^[A-Za-z0-9._/ :-]+$")
_INTERFACE_URL = "https://github.com/file-tunnel/ftnl-interfaces.git"
_SOURCE_REPOSITORIES = {
    "interfaces": "file-tunnel/ftnl-interfaces",
    "rust_desktop": "file-tunnel/ftnl-desktop-app.rs",
    "flutter_desktop": "file-tunnel/ftnl-flutter",
}


def validate_desktop_contract(
    *,
    interfaces_root: Path,
    rust_root: Path,
    source_lock_path: Path,
    flutter_root: Path | None = None,
    flutter_evidence_path: Path | None = None,
    verify_git_revisions: bool = False,
) -> DesktopContractReport:
    if (flutter_root is None) == (flutter_evidence_path is None):
        raise DesktopContractViolation(
            "provide exactly one Flutter checkout or versioned evidence record"
        )
    source_lock = _read_json(source_lock_path)
    sources, contract_revision = _validate_source_lock(source_lock)
    roots = {
        "interfaces": interfaces_root,
        "rust_desktop": rust_root,
    }
    if flutter_root is not None:
        roots["flutter_desktop"] = flutter_root
    if verify_git_revisions:
        for name, root in roots.items():
            actual = _git_revision(root)
            expected = sources[name]["commit"]
            if actual != expected:
                raise DesktopContractViolation(
                    f"{name} checkout is {actual}, expected immutable source {expected}"
                )

    schema = _read_json(interfaces_root / "schema/desktop-workspace.schema.json")
    schema_version, implementations, feature_ids = _validate_schema(schema)
    rust_manifest = _read_json(rust_root / "contracts/desktop-feature-manifest.json")
    if flutter_root is not None:
        flutter_manifest = _read_json(
            flutter_root / "contracts/desktop-feature-manifest.json"
        )
    else:
        flutter_manifest = _validate_flutter_evidence(
            _read_json(flutter_evidence_path), sources
        )
    rust_semantics = _validate_implementation_manifest(
        rust_manifest,
        expected_implementation="rust_desktop",
        implementations=implementations,
        feature_ids=feature_ids,
    )
    flutter_semantics = _validate_implementation_manifest(
        flutter_manifest,
        expected_implementation="flutter_desktop",
        implementations=implementations,
        feature_ids=feature_ids,
    )
    if rust_semantics != flutter_semantics:
        raise DesktopContractViolation(
            "Rust and Flutter feature status pairs must remain exactly equal"
        )

    interface_commit = sources["interfaces"]["commit"]
    _validate_rust_dependency_pin(rust_root, interface_commit)
    if flutter_root is not None:
        _validate_flutter_dependency_pin(flutter_root, interface_commit)

    assembled = {
        "document_type": "parity_manifest",
        "schema_version": schema_version,
        "contract_revision": contract_revision,
        "rust_desktop": rust_manifest,
        "flutter_desktop": flutter_manifest,
    }
    parity_schema = schema["$defs"]["parityManifest"]
    _require_exact_keys(assembled, parity_schema["required"], "parity manifest")
    if parity_schema.get("additionalProperties") is not False:
        raise DesktopContractViolation("parity schema must reject unknown fields")

    return DesktopContractReport(
        contract_revision=contract_revision,
        interface_commit=interface_commit,
        feature_count=len(feature_ids),
        assembled_manifest=assembled,
    )


def _validate_source_lock(
    source_lock: Any,
) -> tuple[Mapping[str, Mapping[str, str]], str]:
    if not isinstance(source_lock, Mapping):
        raise DesktopContractViolation("source lock must be an object")
    _require_exact_keys(source_lock, {"contract_revision", "sources"}, "source lock")
    revision = source_lock["contract_revision"]
    if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
        raise DesktopContractViolation("source lock contract revision is invalid")
    sources = source_lock["sources"]
    if not isinstance(sources, Mapping):
        raise DesktopContractViolation("source lock sources must be an object")
    _require_exact_keys(sources, set(_SOURCE_REPOSITORIES), "source lock sources")
    for name, repository in _SOURCE_REPOSITORIES.items():
        source = sources[name]
        if not isinstance(source, Mapping):
            raise DesktopContractViolation(f"{name} source must be an object")
        _require_exact_keys(source, {"repository", "commit"}, f"{name} source")
        if source["repository"] != repository:
            raise DesktopContractViolation(f"{name} repository is not canonical")
        if not isinstance(source["commit"], str) or not _SHA256.fullmatch(
            source["commit"]
        ):
            raise DesktopContractViolation(f"{name} commit must be a full lowercase SHA")
    return sources, revision


def _validate_schema(schema: Any) -> tuple[int, tuple[str, ...], tuple[str, ...]]:
    if not isinstance(schema, Mapping):
        raise DesktopContractViolation("desktop workspace schema must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise DesktopContractViolation("desktop workspace schema must use Draft 2020-12")
    definitions = schema.get("$defs")
    if not isinstance(definitions, Mapping):
        raise DesktopContractViolation("desktop workspace schema definitions are missing")

    try:
        schema_version = definitions["schemaVersion"]["const"]
        implementations = tuple(definitions["implementation"]["enum"])
        feature_ids = tuple(definitions["featureId"]["enum"])
        manifest_features = definitions["implementationManifest"]["properties"][
            "features"
        ]
    except (KeyError, TypeError) as error:
        raise DesktopContractViolation("desktop manifest schema structure drifted") from error
    if schema_version != 1:
        raise DesktopContractViolation("desktop workspace schema version is unsupported")
    if implementations != ("rust_desktop", "flutter_desktop"):
        raise DesktopContractViolation("desktop implementations are not canonical")
    if (
        not feature_ids
        or len(feature_ids) != len(set(feature_ids))
        or feature_ids != tuple(sorted(feature_ids))
    ):
        raise DesktopContractViolation("feature identifiers must be unique and ordered")
    if manifest_features.get("minItems") != len(feature_ids) or manifest_features.get(
        "maxItems"
    ) != len(feature_ids):
        raise DesktopContractViolation("manifest feature bounds must cover the full enum")
    return schema_version, implementations, feature_ids


def _validate_implementation_manifest(
    manifest: Any,
    *,
    expected_implementation: str,
    implementations: Sequence[str],
    feature_ids: Sequence[str],
) -> tuple[tuple[str, str], ...]:
    if not isinstance(manifest, Mapping):
        raise DesktopContractViolation(f"{expected_implementation} manifest must be an object")
    _require_exact_keys(
        manifest, {"implementation", "features"}, f"{expected_implementation} manifest"
    )
    if (
        manifest["implementation"] != expected_implementation
        or manifest["implementation"] not in implementations
    ):
        raise DesktopContractViolation(
            f"{expected_implementation} manifest identity is incorrect"
        )
    features = manifest["features"]
    if not isinstance(features, list) or len(features) != len(feature_ids):
        raise DesktopContractViolation(
            f"{expected_implementation} must account for every canonical feature"
        )

    actual_ids: list[str] = []
    semantics: list[tuple[str, str]] = []
    for feature in features:
        if not isinstance(feature, Mapping):
            raise DesktopContractViolation("feature support must be an object")
        feature_id = feature.get("feature_id")
        status = feature.get("status")
        if feature_id not in feature_ids:
            raise DesktopContractViolation(f"unknown desktop feature: {feature_id}")
        if status == "implemented":
            _require_exact_keys(
                feature, {"feature_id", "status", "evidence"}, "implemented feature"
            )
            evidence = feature["evidence"]
            if (
                not isinstance(evidence, list)
                or not 1 <= len(evidence) <= 8
                or len(evidence) != len(set(evidence))
                or any(
                    not isinstance(value, str)
                    or not 1 <= len(value) <= 160
                    or not _EVIDENCE.fullmatch(value)
                    for value in evidence
                )
            ):
                raise DesktopContractViolation("implementation evidence is invalid")
        elif status == "planned":
            _require_exact_keys(
                feature, {"feature_id", "status", "follow_up_issue"}, "planned feature"
            )
            if not isinstance(feature["follow_up_issue"], str) or not _DEN_ISSUE.fullmatch(
                feature["follow_up_issue"]
            ):
                raise DesktopContractViolation("planned feature needs a DEN issue")
        elif status == "blocked":
            _require_exact_keys(
                feature,
                {"feature_id", "status", "follow_up_issue", "reason_code"},
                "blocked feature",
            )
            if not isinstance(feature["follow_up_issue"], str) or not _DEN_ISSUE.fullmatch(
                feature["follow_up_issue"]
            ):
                raise DesktopContractViolation("blocked feature needs a DEN issue")
            if feature["reason_code"] not in {
                "missing_platform_runner",
                "missing_platform_permission",
                "missing_signed_artifact",
                "upstream_dependency",
            }:
                raise DesktopContractViolation("blocked feature reason is invalid")
        else:
            raise DesktopContractViolation(f"invalid feature status: {status}")
        actual_ids.append(feature_id)
        semantics.append((feature_id, status))

    if tuple(actual_ids) != tuple(feature_ids):
        raise DesktopContractViolation(
            f"{expected_implementation} features must be complete and schema ordered"
        )
    return tuple(semantics)


def _validate_rust_dependency_pin(root: Path, interface_commit: str) -> None:
    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    dependency = cargo.get("dependencies", {}).get("ftnl-interfaces")
    if not isinstance(dependency, Mapping):
        raise DesktopContractViolation("Rust app must declare ftnl-interfaces")
    if dependency.get("git") != _INTERFACE_URL or dependency.get("rev") != interface_commit:
        raise DesktopContractViolation("Rust app must pin the canonical interface commit")
    lock = (root / "Cargo.lock").read_text(encoding="utf-8")
    source = f"{_INTERFACE_URL}?rev={interface_commit}#{interface_commit}"
    if source not in lock:
        raise DesktopContractViolation("Cargo.lock does not resolve the interface pin")


def _validate_flutter_dependency_pin(root: Path, interface_commit: str) -> None:
    manifest = (root / "pubspec.yaml").read_text(encoding="utf-8")
    lock = (root / "pubspec.lock").read_text(encoding="utf-8")
    manifest_block = _yaml_dependency_block(manifest, "ftnl_interfaces")
    lock_block = _yaml_dependency_block(lock, "ftnl_interfaces")
    if _INTERFACE_URL not in manifest_block or not re.search(
        rf"(?m)^\s+ref:\s*[\"']?{interface_commit}[\"']?\s*$", manifest_block
    ):
        raise DesktopContractViolation("Flutter app must pin the canonical interface commit")
    if _INTERFACE_URL not in lock_block or not re.search(
        rf"(?m)^\s+resolved-ref:\s*[\"']?{interface_commit}[\"']?\s*$", lock_block
    ):
        raise DesktopContractViolation("pubspec.lock does not resolve the interface pin")


def _validate_flutter_evidence(
    evidence: Any, sources: Mapping[str, Mapping[str, str]]
) -> Mapping[str, Any]:
    if not isinstance(evidence, Mapping):
        raise DesktopContractViolation("Flutter evidence must be an object")
    _require_exact_keys(
        evidence,
        {"repository", "commit", "interface_commit", "feature_manifest"},
        "Flutter evidence",
    )
    flutter_source = sources["flutter_desktop"]
    if (
        evidence["repository"] != flutter_source["repository"]
        or evidence["commit"] != flutter_source["commit"]
    ):
        raise DesktopContractViolation("Flutter evidence does not match its source lock")
    if evidence["interface_commit"] != sources["interfaces"]["commit"]:
        raise DesktopContractViolation("Flutter evidence pins a different interface commit")
    manifest = evidence["feature_manifest"]
    if not isinstance(manifest, Mapping):
        raise DesktopContractViolation("Flutter evidence manifest must be an object")
    return manifest


def _yaml_dependency_block(text: str, dependency: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(dependency)}:\s*$.*?(?=^  [A-Za-z0-9_]+:\s*$|\Z)",
        text,
    )
    if match is None:
        raise DesktopContractViolation(f"missing dependency block: {dependency}")
    return match.group(0)


def _require_exact_keys(value: Mapping[str, Any], required: Any, label: str) -> None:
    if set(value) != set(required):
        raise DesktopContractViolation(f"{label} fields are not canonical")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DesktopContractViolation(f"cannot read canonical JSON: {path}") from error


def _git_revision(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the canonical Rust/Flutter desktop contract as one release unit."
    )
    parser.add_argument("--interfaces", required=True, type=Path)
    parser.add_argument("--rust", required=True, type=Path)
    flutter_source = parser.add_mutually_exclusive_group(required=True)
    flutter_source.add_argument("--flutter", type=Path)
    flutter_source.add_argument("--flutter-evidence", type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--verify-git-revisions", action="store_true")
    args = parser.parse_args(argv)
    report = validate_desktop_contract(
        interfaces_root=args.interfaces,
        rust_root=args.rust,
        source_lock_path=args.source_lock,
        flutter_root=args.flutter,
        flutter_evidence_path=args.flutter_evidence,
        verify_git_revisions=args.verify_git_revisions,
    )
    print(
        f"validated {report.contract_revision}: {report.feature_count} paired desktop "
        f"features at interface {report.interface_commit}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
