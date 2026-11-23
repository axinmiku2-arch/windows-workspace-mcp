"""Offline fixtures for read-only PE inspection and deterministic DOCX tasks."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import struct
import subprocess  # Preload native POSIX subprocess before the narrow Windows import shim below.
import sys
import tempfile
import types
import unittest
import uuid
from unittest.mock import patch
from xml.etree import ElementTree as ET
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))


class UpgradePresets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        shims = {} if os.name == "nt" else {"msvcrt": types.ModuleType("msvcrt")}
        # Format fixtures never exercise the Windows-only file bridge or Win32 publication.
        with patch.dict(sys.modules, shims), patch.dict(os.environ, {"WINDOWS_WORKSPACE_MCP_STATE": str(self.root / "state")}):
            import task_documents
            import task_files
            import task_recipes
            import task_verification
            import project_tasks
        self.doc, self.files, self.recipes, self.verify, self.tasks = (
            task_documents, task_files, task_recipes, task_verification, project_tasks,
        )

    def write(self, name, data):
        file = self.root / name
        file.write_bytes(data)
        return file

    def compile_doc(self, data):
        source = self.write("source.txt", data)
        out = self.root / "out.docx"
        return self.doc.convert(source, out, lambda *_args, **_kw: None,
                                self.verify.stamp(source.stat())), out

    def pe_bytes(self, magic=0x20b, flags=0x0002, machine=0x8664):
        dos = bytearray(64)
        dos[:2] = b"MZ"
        struct.pack_into("<I", dos, 60, 64)
        opt = bytearray(112)
        struct.pack_into("<H", opt, 0, magic)
        struct.pack_into("<H", opt, 68, 3)
        return bytes(dos) + b"PE\x00\x00" + struct.pack(
            "<HHIIIHH", machine, 1, 0, 0, 0, len(opt), flags,
        ) + bytes(opt) + bytes(40)

    def test_docx_preserves_chinese_tabs_and_xml_literals(self):
        data = "  中文 <&>\tтест\r\n\rthird\n".encode("utf-8-sig")
        result, output = self.compile_doc(data)
        self.assertEqual(result["source_bytes"], len(data))
        self.assertEqual(result["paragraphs"], 4)
        self.assertEqual(result["size_bytes"], output.stat().st_size)
        self.assertEqual(result["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        with zipfile.ZipFile(output) as pkg:
            self.assertIsNone(pkg.testzip())
            self.assertEqual(set(pkg.namelist()), {"[Content_Types].xml", "_rels/.rels", "word/document.xml"})
            body = ET.fromstring(pkg.read("word/document.xml"))
        ns = {"w": self.doc.WORD_NS}
        self.assertEqual([node.text for node in body.findall(".//w:t", ns)],
                         ["  中文 <&>", "тест", None, "third", None])
        self.assertEqual(len(body.findall(".//w:tab", ns)), 1)

    def test_docx_rejects_bad_utf8_xml_controls_length_and_lines(self):
        for data in (b"\xff", b"\x00", b"a" * (256 * 1024 + 1), b"\n" * 4000, b"\t" * 4097):
            with self.subTest(length=len(data)):
                with self.assertRaises(ValueError):
                    self.compile_doc(data)
                self.assertFalse((self.root / "out.docx").exists())

    def test_docx_verifies_stable_input_and_no_output_overwrite(self):
        marked = self.write("source.txt", b"original")
        old_stamp = self.verify.stamp(marked.stat())
        marked.write_bytes(b"changed source")
        out = self.write("out.docx", b"existing")
        with self.assertRaisesRegex(ValueError, "changed"):
            self.doc.convert(marked, out, lambda *_a, **_kw: None, old_stamp)
        with self.assertRaises(FileExistsError):
            self.compile_doc(b"correct current source")
        self.assertEqual(out.read_bytes(), b"existing")

    def test_docx_deterministic_for_same_input(self):
        data = "same text\t 中文".encode()
        result, output = self.compile_doc(data)
        output.unlink()
        repeated, _ = self.compile_doc(data)
        self.assertEqual(repeated, result)

    def test_pe_is_static_header_only(self):
        source = self.write("app.exe", self.pe_bytes())
        checkpoint = lambda *_a, **_kw: None
        with patch.object(self.tasks.subprocess, "Popen", side_effect=AssertionError("must not execute")):
            normal = self.verify.inspect_pe(source, checkpoint, self.verify.stamp(source.stat()))
        self.assertEqual((normal["architecture"], normal["format"], normal["subsystem_code"]), ("x64", "PE32+", 3))
        self.assertTrue(normal["static_header_only"])
        self.assertFalse(normal["declares_dll"])
        with self.subTest("32-bit DLL"):
            dll = self.write("lib.dll", self.pe_bytes(0x10b, 0x2002, 0x14c))
            header = self.verify.inspect_pe(dll, checkpoint, self.verify.stamp(dll.stat()))
            self.assertEqual((header["architecture"], header["format"], header["declares_dll"]), ("x86", "PE32", True))

    def test_pe_rejects_truncated_and_invalid_header(self):
        for data in (b"not a PE", self.pe_bytes()[:-1], self.pe_bytes(magic=1)):
            source = self.write("app.exe", data)
            with self.assertRaises(ValueError):
                self.verify.inspect_pe(source, lambda *_a, **_kw: None, self.verify.stamp(source.stat()))
        with self.assertRaises(ValueError):
            self.verify.arguments("pe_inspect", {"command": "ignored"})

    def test_recipe_catalog_exposes_safe_non_execution_templates(self):
        for name in ("校验文本后生成 DOCX", "静态检查 Windows 程序"):
            normalized = self.recipes.normalize(self.recipes.TEMPLATES[name])
            self.assertEqual(normalized["target"], "file")
            self.assertTrue(all(x["preset"] not in self.tasks.PROJECT_PRESETS for x in normalized["steps"]))
        unsafe = {"id": "unsafe", "label": "unsafe", "target": "directory",
                  "steps": [{"preset": "npm_build", "parameters": {"command": "invalid"}}]}
        with self.assertRaises(ValueError):
            self.recipes.normalize(unsafe)
        for mode in ("ask", "rules", "full"):
            cfg = {"workspace_unified": True, "approval_mode": mode}
            self.assertEqual(self.tasks._automatic("text_to_docx", cfg), mode == "full")
            self.assertEqual(self.tasks._automatic("pe_inspect", cfg), mode in {"rules", "full"})
            for preset in ("git_status", "git_diff", "python_unittest", "npm_test", "npm_build"):
                self.assertFalse(self.tasks._automatic(preset, cfg))

    @unittest.skipUnless(os.name == "nt", "Requires Windows for atomic workspace publication")
    def test_windows_docx_publishes_and_refuses_existing_destination(self):
        source = self.write("source.txt", "写出 DOCX".encode())
        destination = self.root / "localized.docx"
        job = {"preset": "text_to_docx", "job_id": uuid.uuid4().hex, "destination_path": destination.name,
               "file_stamp": self.verify.stamp(source.stat())}
        stage_log = []
        result = self.files.execute(self.root, source, job, lambda *_a, **_kw: None, stage_log.append)
        self.assertTrue(zipfile.is_zipfile(destination))
        self.assertFalse(stage_log[-1]["directory"])
        self.assertEqual(result["format"], "docx")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.files.execute(self.root, source, job, lambda *_a, **_kw: None, stage_log.append)


if __name__ == "__main__":
    unittest.main(verbosity=2)
