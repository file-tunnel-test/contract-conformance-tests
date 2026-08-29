import copy
import json
import tempfile
import unittest
from pathlib import Path

from deep_tests.desktop_contract import (
    DesktopContractViolation,
    validate_desktop_contract,
)


class DesktopContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.interfaces = root / "interfaces"
        self.rust = root / "rust"
        self.flutter = root / "flutter"
        self.source_lock = root / "desktop-contract-sources.json"
        self.flutter_evidence = root / "flutter-desktop-evidence.json"
        for directory in (
            self.interfaces / "schema",
            self.rust / "contracts",
            self.flutter / "contracts",
        ):
            directory.mkdir(parents=True)

        self.interface_commit = "a" * 40
        self.feature_ids = [
            "clipboard.capture.pause",
            "desktop.window.regular",
        ]
        self.schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {
                "schemaVersion": {"const": 1},
                "implementation": {
                    "enum": ["rust_desktop", "flutter_desktop"]
                },
                "featureId": {"enum": self.feature_ids},
                "implementationManifest": {
                    "properties": {
                        "features": {"minItems": 2, "maxItems": 2}
                    }
                },
                "parityManifest": {
                    "required": [
                        "document_type",
                        "schema_version",
                        "contract_revision",
                        "rust_desktop",
                        "flutter_desktop",
                    ],
                    "additionalProperties": False,
                },
            },
        }
        self.rust_manifest = self._manifest("rust_desktop", "src/workspace.rs tests")
        self.flutter_manifest = self._manifest(
            "flutter_desktop", "lib/clipboard_workspace.dart tests"
        )
        self._write_json(
            self.interfaces / "schema/desktop-workspace.schema.json", self.schema
        )
        self._write_json(
            self.rust / "contracts/desktop-feature-manifest.json", self.rust_manifest
        )
        self._write_json(
            self.flutter / "contracts/desktop-feature-manifest.json",
            self.flutter_manifest,
        )
        self._write_json(
            self.source_lock,
            {
                "contract_revision": "DEN-3384.v1",
                "sources": {
                    "interfaces": {
                        "repository": "file-tunnel/ftnl-interfaces",
                        "commit": self.interface_commit,
                    },
                    "rust_desktop": {
                        "repository": "file-tunnel/ftnl-desktop-app.rs",
                        "commit": "b" * 40,
                    },
                    "flutter_desktop": {
                        "repository": "file-tunnel/ftnl-flutter",
                        "commit": "c" * 40,
                    },
                },
            },
        )
        self._write_dependency_files()

    def test_assembles_both_manifests_against_one_contract_revision(self) -> None:
        report = self._validate()
        self.assertEqual(report.contract_revision, "DEN-3384.v1")
        self.assertEqual(report.interface_commit, self.interface_commit)
        self.assertEqual(report.feature_count, 2)
        self.assertEqual(
            set(report.assembled_manifest),
            {
                "document_type",
                "schema_version",
                "contract_revision",
                "rust_desktop",
                "flutter_desktop",
            },
        )

    def test_rejects_cross_client_status_drift(self) -> None:
        changed = copy.deepcopy(self.flutter_manifest)
        changed["features"][0] = {
            "feature_id": self.feature_ids[0],
            "status": "planned",
            "follow_up_issue": "DEN-3900",
        }
        self._write_json(
            self.flutter / "contracts/desktop-feature-manifest.json", changed
        )
        with self.assertRaisesRegex(
            DesktopContractViolation, "status pairs must remain exactly equal"
        ):
            self._validate()

    def test_rejects_missing_reordered_or_unknown_features(self) -> None:
        vectors = [
            self.rust_manifest["features"][:-1],
            list(reversed(self.rust_manifest["features"])),
            [
                self.rust_manifest["features"][0],
                {
                    "feature_id": "clipboard.unknown",
                    "status": "implemented",
                    "evidence": ["tests"],
                },
            ],
        ]
        for features in vectors:
            with self.subTest(features=features):
                changed = copy.deepcopy(self.rust_manifest)
                changed["features"] = features
                self._write_json(
                    self.rust / "contracts/desktop-feature-manifest.json", changed
                )
                with self.assertRaises(DesktopContractViolation):
                    self._validate()

    def test_rejects_unknown_fields_and_noncanonical_evidence(self) -> None:
        changed = copy.deepcopy(self.rust_manifest)
        changed["unexpected"] = True
        self._write_json(
            self.rust / "contracts/desktop-feature-manifest.json", changed
        )
        with self.assertRaisesRegex(DesktopContractViolation, "fields are not canonical"):
            self._validate()

        changed = copy.deepcopy(self.rust_manifest)
        changed["features"][0]["evidence"] = ["same", "same"]
        self._write_json(
            self.rust / "contracts/desktop-feature-manifest.json", changed
        )
        with self.assertRaisesRegex(DesktopContractViolation, "evidence is invalid"):
            self._validate()

    def test_rejects_dependency_pin_drift_in_either_client(self) -> None:
        (self.rust / "Cargo.toml").write_text(
            "[dependencies]\n"
            'ftnl-interfaces = { git = "https://github.com/file-tunnel/ftnl-interfaces.git", '
            f'rev = "{"d" * 40}" }}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(DesktopContractViolation, "Rust app must pin"):
            self._validate()

        self._write_dependency_files()
        pubspec = (self.flutter / "pubspec.yaml").read_text(encoding="utf-8")
        (self.flutter / "pubspec.yaml").write_text(
            pubspec.replace(self.interface_commit, "d" * 40), encoding="utf-8"
        )
        with self.assertRaisesRegex(DesktopContractViolation, "Flutter app must pin"):
            self._validate()

    def test_rejects_mutable_or_misdirected_source_locks(self) -> None:
        lock = json.loads(self.source_lock.read_text(encoding="utf-8"))
        for mutation in ("short_sha", "wrong_repository", "unknown_field"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(lock)
                if mutation == "short_sha":
                    changed["sources"]["interfaces"]["commit"] = "main"
                elif mutation == "wrong_repository":
                    changed["sources"]["interfaces"]["repository"] = "other/interfaces"
                else:
                    changed["allow_drift"] = True
                self._write_json(self.source_lock, changed)
                with self.assertRaises(DesktopContractViolation):
                    self._validate()

    def test_versioned_flutter_evidence_matches_source_and_interface_locks(self) -> None:
        evidence = {
            "repository": "file-tunnel/ftnl-flutter",
            "commit": "c" * 40,
            "interface_commit": self.interface_commit,
            "feature_manifest": self.flutter_manifest,
        }
        self._write_json(self.flutter_evidence, evidence)
        report = validate_desktop_contract(
            interfaces_root=self.interfaces,
            rust_root=self.rust,
            source_lock_path=self.source_lock,
            flutter_evidence_path=self.flutter_evidence,
        )
        self.assertEqual(report.feature_count, 2)

        for field, value in (
            ("repository", "other/flutter"),
            ("commit", "d" * 40),
            ("interface_commit", "e" * 40),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(evidence)
                changed[field] = value
                self._write_json(self.flutter_evidence, changed)
                with self.assertRaises(DesktopContractViolation):
                    validate_desktop_contract(
                        interfaces_root=self.interfaces,
                        rust_root=self.rust,
                        source_lock_path=self.source_lock,
                        flutter_evidence_path=self.flutter_evidence,
                    )

    def _validate(self):
        return validate_desktop_contract(
            interfaces_root=self.interfaces,
            rust_root=self.rust,
            flutter_root=self.flutter,
            source_lock_path=self.source_lock,
        )

    def _manifest(self, implementation: str, evidence: str) -> dict:
        return {
            "implementation": implementation,
            "features": [
                {
                    "feature_id": feature_id,
                    "status": "implemented",
                    "evidence": [evidence],
                }
                for feature_id in self.feature_ids
            ],
        }

    def _write_dependency_files(self) -> None:
        (self.rust / "Cargo.toml").write_text(
            "[dependencies]\n"
            'ftnl-interfaces = { git = "https://github.com/file-tunnel/ftnl-interfaces.git", '
            f'rev = "{self.interface_commit}" }}\n',
            encoding="utf-8",
        )
        (self.rust / "Cargo.lock").write_text(
            "[[package]]\n"
            'name = "ftnl-interfaces"\n'
            'source = "git+https://github.com/file-tunnel/ftnl-interfaces.git?'
            f'rev={self.interface_commit}#{self.interface_commit}"\n',
            encoding="utf-8",
        )
        (self.flutter / "pubspec.yaml").write_text(
            "dependencies:\n"
            "  ftnl_interfaces:\n"
            "    git:\n"
            "      url: https://github.com/file-tunnel/ftnl-interfaces.git\n"
            f"      ref: {self.interface_commit}\n"
            "      path: generated/dart\n"
            "  other: any\n",
            encoding="utf-8",
        )
        (self.flutter / "pubspec.lock").write_text(
            "packages:\n"
            "  ftnl_interfaces:\n"
            '    dependency: "direct main"\n'
            "    description:\n"
            "      path: generated/dart\n"
            f'      ref: "{self.interface_commit}"\n'
            f'      resolved-ref: "{self.interface_commit}"\n'
            '      url: "https://github.com/file-tunnel/ftnl-interfaces.git"\n'
            "    source: git\n"
            "  other:\n"
            "    dependency: transitive\n",
            encoding="utf-8",
        )

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
