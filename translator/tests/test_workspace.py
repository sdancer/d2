from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from d2wasm.debugdb import SCHEMA
from d2wasm.workspace import LeaseError, SchemaVersionError, TranslationStore


class TranslationStoreTests(unittest.TestCase):
    def make_store(self, directory: str) -> tuple[TranslationStore, str, str, str]:
        store = TranslationStore(Path(directory) / "workspace.sqlite")
        manifest = {
            "schema_version": 1,
            "entry_va": 0x401000,
            "modules": [
                {
                    "runtime_name": "fixture.exe",
                    "source": "fixture.exe",
                    "load_base": 0x400000,
                    "sha256": "00" * 32,
                }
            ],
        }
        project_id = store.register_project(manifest)
        inventory = {
            "runtime_name": "fixture.exe",
            "source": "fixture.exe",
            "sha256": "00" * 32,
            "file_size": 8,
            "image_base": 0x400000,
            "image_size": 0x2000,
            "entry_rva": 0x1000,
            "load_base": 0x400000,
            "sections": [
                {
                    "name": ".text",
                    "rva": 0x1000,
                    "virtual_size": 8,
                    "file_size": 8,
                    "executable": True,
                }
            ],
            "imports": [],
            "exports": [],
        }
        module_id = store.register_module(
            project_id,
            inventory,
            binary_sha256="00" * 32,
            inventory=inventory,
        )
        tool_id = store.register_tool_version("test", "1")
        run_id = store.register_analysis_run(
            project_id, tool_id, {"mode": "test"}, {"fixture": True}
        )
        return store, project_id, module_id, run_id

    def test_fresh_schema_and_future_version_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workspace.sqlite"
            with TranslationStore(path) as store:
                self.assertEqual(store.schema_version, 2)
                self.assertEqual(
                    store.connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()[0],
                    "2",
                )
                self.assertEqual(
                    store.connection.execute("PRAGMA journal_mode").fetchone()[0],
                    "wal",
                )
                self.assertEqual(
                    store.connection.execute("PRAGMA foreign_keys").fetchone()[0],
                    1,
                )
                self.assertTrue(store.integrity_check()["ok"])
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA user_version=99")
            connection.close()
            with self.assertRaises(SchemaVersionError):
                TranslationStore(path)

    def test_v1_migration_preserves_compatibility_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite"
            connection = sqlite3.connect(path)
            connection.executescript(SCHEMA)
            connection.executemany(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                [("schema_version", "1"), ("entry_va", str(0x401000))],
            )
            connection.execute(
                """INSERT INTO modules
                   (id, runtime_name, source, image_base, load_base, image_size,
                    entry_rva, entry_va) VALUES (1, 'fixture.exe', 'fixture.exe',
                    4194304, 4194304, 8192, 4096, 4198400)"""
            )
            connection.execute(
                """INSERT INTO sections
                   (module_id, name, rva, va, virtual_size, file_size, executable)
                   VALUES (1, '.text', 4096, 4198400, 1, 1, 1)"""
            )
            connection.execute("INSERT INTO roots VALUES (1, 4096, 4198400)")
            connection.execute(
                """INSERT INTO blocks
                   (va, module_id, rva, terminator, instruction_count)
                   VALUES (4198400, 1, 4096, 'ret', 1)"""
            )
            connection.execute(
                """INSERT INTO instructions
                   (va, module_id, block_va, rva, sequence, size, bytes, mnemonic, op_str)
                   VALUES (4198400, 1, 4198400, 4096, 0, 1, ?, 'ret', '')""",
                (b"\xc3",),
            )
            connection.commit()
            connection.close()

            with TranslationStore(path) as store:
                self.assertEqual(store.schema_version, 2)
                self.assertEqual(
                    store.connection.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    store.connection.execute(
                        "SELECT COUNT(*) FROM block_revisions"
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    store.connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()[0],
                    "2",
                )
            with TranslationStore(path) as reopened:
                self.assertEqual(
                    reopened.connection.execute(
                        "SELECT COUNT(*) FROM block_revisions"
                    ).fetchone()[0],
                    1,
                )

    def test_work_leases_retry_and_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _, module_id, run_id = self.make_store(directory)
            try:
                item_id = store.enqueue_work(
                    run_id,
                    module_id,
                    0x1000,
                    entry_state={"constants": {"eax": 1}},
                )
                claimed = store.claim_work(run_id, "worker", lease_seconds=1, now=0)
                self.assertEqual(claimed["work_item_id"], item_id)
                self.assertEqual(store.recover_expired_leases(now=2, run_id=run_id), 1)
                self.assertEqual(store.work_counts(run_id)["pending"], 1)
                claimed = store.claim_work(run_id, "worker", lease_seconds=10, now=3)
                store.finish_work(
                    item_id,
                    claimed["lease_token"],
                    state="failed",
                    error="fixture failure",
                )
                self.assertEqual(store.work_counts(run_id)["failed"], 1)
                self.assertEqual(store.retry_work(run_id=run_id), 1)
                self.assertEqual(store.work_counts(run_id)["pending"], 1)

                store.persist_block_revision(
                    run_id,
                    module_id,
                    0x1000,
                    instructions=[
                        {
                            "rva": 0x1000,
                            "size": 1,
                            "bytes": b"\xc3",
                            "mnemonic": "ret",
                            "op_str": "",
                        }
                    ],
                    edges=[
                        {
                            "source_instruction_rva": 0x1000,
                            "target_module_version_id": module_id,
                            "target_rva": 0x1001,
                            "kind": "fallthrough",
                            "resolution": "pending",
                            "details": {"entry_state": {"constants": {"eax": 7}}},
                        }
                    ],
                    terminator="fallthrough",
                    refresh_projection=False,
                )
                self.assertEqual(store.reconcile_work(run_id), 1)
                target = store.connection.execute(
                    "SELECT entry_state_json FROM work_items WHERE target_rva=4097"
                ).fetchone()
                self.assertIn('"eax":7', target[0])
            finally:
                store.close()

    def test_weaker_state_discovered_during_lease_is_requeued(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _, module_id, run_id = self.make_store(directory)
            try:
                item_id = store.enqueue_work(
                    run_id,
                    module_id,
                    0x1000,
                    entry_state={"constants": {"eax": 1}},
                )
                claimed = store.claim_work(run_id, "worker", lease_seconds=10, now=0)
                store.enqueue_work(
                    run_id,
                    module_id,
                    0x1000,
                    entry_state={"constants": {}},
                )
                store.finish_work(
                    item_id,
                    claimed["lease_token"],
                    state="completed",
                )
                row = store.connection.execute(
                    "SELECT state, entry_state_json FROM work_items WHERE work_item_id=?",
                    (item_id,),
                ).fetchone()
                self.assertEqual(row["state"], "pending")
                self.assertEqual(json.loads(row["entry_state_json"]), {"constants": {}})
            finally:
                store.close()

    def test_stale_lease_cannot_select_a_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _, module_id, run_id = self.make_store(directory)
            try:
                item_id = store.enqueue_work(run_id, module_id, 0x1000)
                first = store.claim_work(run_id, "first", lease_seconds=1, now=0)
                store.recover_expired_leases(now=2, run_id=run_id)
                second = store.claim_work(run_id, "second", lease_seconds=10, now=3)
                self.assertIsNotNone(second)
                with self.assertRaises(LeaseError):
                    store.persist_claimed_block(
                        item_id,
                        first["lease_token"],
                        run_id,
                        module_id,
                        0x1000,
                        instructions=[
                            {
                                "rva": 0x1000,
                                "size": 1,
                                "bytes": b"\xc3",
                                "mnemonic": "ret",
                                "op_str": "",
                            }
                        ],
                        terminator="ret",
                    )
                self.assertEqual(
                    store.connection.execute(
                        "SELECT COUNT(*) FROM run_block_selections WHERE run_id=?",
                        (run_id,),
                    ).fetchone()[0],
                    0,
                )
            finally:
                store.close()

    def test_exhaustive_classifications_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _, module_id, run_id = self.make_store(directory)
            try:
                totals = store.save_byte_classifications(
                    run_id,
                    module_id,
                    [
                        (0x1000, 0x1002, "confirmed_code"),
                        (0x1002, 0x1008, "unresolved"),
                    ],
                    mapped_executable_bytes=8,
                )
                self.assertEqual(totals["total"], 8)
                with self.assertRaises(ValueError):
                    store.save_byte_classifications(
                        run_id,
                        module_id,
                        [(0x1000, 0x1007, "unresolved")],
                        mapped_executable_bytes=8,
                    )
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
