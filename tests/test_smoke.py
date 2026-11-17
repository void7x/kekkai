"""Unit tests for bounded harness smoke validation."""

from __future__ import annotations

import struct
import tempfile
import unittest
import zlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from engine.adapters.config import (
    AdapterConfig,
    FuzzerConfig,
    ResourceLimits,
    TargetConfig,
)
from engine.fuzzing.smoke import (
    HarnessSmokeError,
    LIBPNG_SEED_CASES,
    run_harness_smoke,
)



_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_ADAM7_TEST_PASSES = (
    (0, 0, 8, 8),
    (4, 0, 8, 8),
    (0, 4, 4, 8),
    (2, 0, 4, 4),
    (0, 2, 2, 4),
    (1, 0, 2, 2),
    (0, 1, 1, 2),
)


def _test_png_chunk(kind: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(kind + payload) & 0xffffffff
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def _test_png_image_data(
    width: int,
    height: int,
    bit_depth: int,
    color_type: int,
    interlace: int,
) -> bytes:
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    bits_per_pixel = channels * bit_depth
    passes = _ADAM7_TEST_PASSES if interlace else ((0, 0, 1, 1),)
    raw = bytearray()

    for x_start, y_start, x_step, y_step in passes:
        pass_width = (
            (width - x_start + x_step - 1) // x_step
            if width > x_start else 0
        )
        pass_height = (
            (height - y_start + y_step - 1) // y_step
            if height > y_start else 0
        )
        if not pass_width or not pass_height:
            continue

        row_bytes = (pass_width * bits_per_pixel + 7) // 8
        for _ in range(pass_height):
            raw.append(0)
            raw.extend(bytes(row_bytes))

    return zlib.compress(bytes(raw))


def _make_test_png(
    *,
    width: int = 1,
    height: int = 1,
    bit_depth: int = 8,
    color_type: int = 6,
    interlace: int = 0,
    text_payloads: tuple[bytes, ...] = (),
    text_payloads_after_idat: tuple[bytes, ...] = (),
    include_iend: bool = True,
    valid_image_data: bool = True,
) -> bytes:
    ihdr = struct.pack(
        ">IIBBBBB",
        width, height, bit_depth, color_type, 0, 0, interlace,
    )
    data = bytearray(_PNG_SIGNATURE + _test_png_chunk(b"IHDR", ihdr))

    for payload in text_payloads:
        data.extend(_test_png_chunk(b"tEXt", payload))

    if valid_image_data:
        image_data = _test_png_image_data(
            width, height, bit_depth, color_type, interlace
        )
    else:
        image_data = zlib.compress(b"")

    data.extend(_test_png_chunk(b"IDAT", image_data))

    for payload in text_payloads_after_idat:
        data.extend(_test_png_chunk(b"tEXt", payload))

    if include_iend:
        data.extend(_test_png_chunk(b"IEND", b""))

    return bytes(data)


class HarnessSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

        self.root = self.base / "repository"
        self.root.mkdir()

        self.workspace = self.base / "workspace"
        self.workspace.mkdir()

        source_dir = self.workspace / "libpng"
        source_dir.mkdir()

        harness_source_dir = self.root / "targets" / "libpng"
        harness_source_dir.mkdir(parents=True)
        harness_source = harness_source_dir / "png_read_harness.c"
        harness_source.write_text("/* test source */\n", encoding="utf-8")

        binary_dir = self.workspace / "build"
        binary_dir.mkdir()
        self.binary = binary_dir / "kekkai_png_harness"
        self.binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.binary.chmod(0o755)

        self.seed_dir = self.workspace / "seeds"
        self.seed_dir.mkdir()

        fixtures = {
            "valid.png": _make_test_png(),
            "adam7.png": _make_test_png(
                width=8, height=8, interlace=1
            ),
            "malformed.png": b"not a png file!!",
            "truncated.png": _make_test_png(include_iend=False),
            "width_over_limit.png": _make_test_png(
                width=8193, valid_image_data=False
            ),
            "height_over_limit.png": _make_test_png(
                height=8193, valid_image_data=False
            ),
            "pixels_over_limit.png": _make_test_png(
                width=8192, height=2048, valid_image_data=False
            ),
            "row_boundary_64k.png": _make_test_png(
                width=8192, height=1, bit_depth=16
            ),
            "chunk_over_limit.png": _make_test_png(
                text_payloads=(b"Comment\\x00" + b"x" * (262145 - 8),)
            ),
            "chunk_cache_over_limit.png": _make_test_png(
                text_payloads=tuple(
                    f"K{i:03d}".encode("ascii") + b"\\x00v"
                    for i in range(130)
                )
            ),
        }

        for _, filename in LIBPNG_SEED_CASES:
            (self.seed_dir / filename).write_bytes(fixtures[filename])

        output_parent = self.workspace / "output"
        output_parent.mkdir()

        self.config = AdapterConfig(
            schema_version=1,
            target=TargetConfig(
                name="libpng",
                version="1.6.59",
                source_dir=source_dir,
                harness_source=harness_source,
                harness_binary=self.binary,
                seed_dir=self.seed_dir,
                output_parent=output_parent,
            ),
            fuzzer=FuzzerConfig(
                executable="afl-fuzz",
                expected_version="4.33c",
            ),
            limits=ResourceLimits(
                duration_seconds=300,
                memory_mib=512,
                timeout_ms=1000,
                max_input_bytes=8 * 1024 * 1024,
            ),
            config_path=self.root / "adapter.toml",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def fake_run(self, argv, **kwargs):
        kwargs["stdout"].write(b"smoke stdout")
        kwargs["stderr"].write(b"smoke diagnostic")

        input_name = Path(argv[1]).name
        return_code = 2 if input_name == "missing-input.png" else 0

        return SimpleNamespace(returncode=return_code)

    def run_smoke_with_fake_process(self, side_effect=None):
        process = side_effect or self.fake_run

        with (
            patch(
                "engine.fuzzing.smoke.os.geteuid",
                return_value=1000,
            ),
            patch(
                "engine.fuzzing.smoke.run_process_group",
                side_effect=process,
            ) as mocked_run,
        ):
            report = run_harness_smoke(self.config, self.root)

        return report, mocked_run

    def test_rejects_png_decompression_bomb(self) -> None:
        from engine.fuzzing.smoke import _validate_png_image_data

        compressed = zlib.compress(b"\x00" + b"A" * (1024 * 1024))
        chunks = ((b"IDAT", compressed),)
        ihdr = (1, 1, 8, 6, 0, 0, 0)

        with self.assertRaisesRegex(ValueError, "beyond the decompressed size"):
            _validate_png_image_data(ihdr, chunks)

    def test_rejects_fixture_with_wrong_semantic_metadata(self) -> None:
        (self.seed_dir / "adam7.png").write_bytes(
            _make_test_png(width=8, height=8, interlace=0)
        )

        report, mocked_run = self.run_smoke_with_fake_process()
        adam7 = next(
            result for result in report.results if result.name == "adam7_png"
        )

        self.assertFalse(report.passed)
        self.assertEqual(adam7.status, "failed")
        self.assertIn("semantic validation failed", adam7.message)
        self.assertEqual(mocked_run.call_count, 12)

    def test_rejects_fixture_with_invalid_chunk_crc(self) -> None:
        path = self.seed_dir / "valid.png"
        damaged = bytearray(path.read_bytes())
        idat_offset = damaged.index(b"IDAT")
        damaged[idat_offset + 4] ^= 0x01
        path.write_bytes(damaged)

        report, mocked_run = self.run_smoke_with_fake_process()
        valid = next(
            result for result in report.results if result.name == "valid_png"
        )

        self.assertFalse(report.passed)
        self.assertEqual(valid.status, "failed")
        self.assertIn("CRC mismatch", valid.message)
        self.assertEqual(mocked_run.call_count, 12)

    def test_rejects_tEXt_chunk_without_keyword_separator(self) -> None:
        from engine.fuzzing.smoke import _validate_seed_fixture

        path = self.seed_dir / "valid.png"
        path.write_bytes(_make_test_png(text_payloads=(b"Comment text",)))
        with self.assertRaisesRegex(ValueError, "NUL separator"):
            _validate_seed_fixture("valid_png", path)

    def test_chunk_cache_limit_counts_pre_and_post_idat_separately(self) -> None:
        from engine.fuzzing.smoke import _validate_seed_fixture

        before = tuple(
            f"B{i:03d}".encode("ascii") + b"\x00v"
            for i in range(70)
        )
        after = tuple(
            f"A{i:03d}".encode("ascii") + b"\x00v"
            for i in range(70)
        )
        path = self.seed_dir / "chunk_cache_over_limit.png"
        path.write_bytes(
            _make_test_png(
                text_payloads=before,
                text_payloads_after_idat=after,
            )
        )
        with self.assertRaisesRegex(ValueError, "within either info structure"):
            _validate_seed_fixture("chunk_cache_limit", path)

    def test_valid_smoke_run_executes_all_expected_cases(self) -> None:
        report, mocked_run = self.run_smoke_with_fake_process()

        self.assertTrue(report.passed, report.format())
        self.assertEqual(len(report.results), 13)
        self.assertEqual(mocked_run.call_count, 13)

        self.assertIn(
            "missing_input_file",
            [result.name for result in report.results],
        )

        for call in mocked_run.call_args_list:
            argv = call.args[0]
            options = call.kwargs

            self.assertIsInstance(argv, list)
            self.assertEqual(len(argv), 2)
            self.assertEqual(argv[0], str(self.binary.resolve()))
            self.assertFalse(options["shell"])
            self.assertEqual(options["timeout"], 5.0)
            self.assertEqual(
                options["env"]["KEKKAI_HARNESS_DIAGNOSTICS"],
                "1",
            )

        self.assertIn("smoke diagnostic", report.results[0].stderr)

    def test_applies_configured_memory_limit(self) -> None:
        import resource

        report, mocked_run = self.run_smoke_with_fake_process()
        self.assertTrue(report.passed, report.format())

        callback = mocked_run.call_args_list[0].kwargs["preexec_fn"]

        with (
            patch(
                "resource.getrlimit",
                return_value=(
                    resource.RLIM_INFINITY,
                    resource.RLIM_INFINITY,
                ),
            ),
            patch("resource.setrlimit") as set_limit,
        ):
            callback()

        expected_bytes = 512 * 1024 * 1024
        calls = set_limit.call_args_list

        self.assertEqual(len(calls), 2)
        self.assertEqual(
            calls[0].args,
            (
                resource.RLIMIT_AS,
                (expected_bytes, expected_bytes),
            ),
        )
        self.assertEqual(
            calls[1].args,
            (
                resource.RLIMIT_FSIZE,
                (64 * 1024, 64 * 1024),
            ),
        )

    def test_preserves_existing_address_space_and_file_limits(self) -> None:
        import resource

        config = self.config
        callback = __import__(
            "engine.fuzzing.smoke",
            fromlist=["_memory_limit_callback"],
        )._memory_limit_callback(config.limits.memory_mib)

        def existing_limit(resource_id):
            if resource_id == resource.RLIMIT_AS:
                return (64 * 1024 * 1024, 256 * 1024 * 1024)
            if resource_id == resource.RLIMIT_FSIZE:
                return (32 * 1024, 128 * 1024)
            raise AssertionError("Unexpected resource limit")

        with (
            patch("resource.getrlimit", side_effect=existing_limit),
            patch("resource.setrlimit") as set_limit,
        ):
            callback()

        calls = set_limit.call_args_list
        self.assertEqual(
            calls[0].args,
            (resource.RLIMIT_AS, (64 * 1024 * 1024, 64 * 1024 * 1024)),
        )
        self.assertEqual(
            calls[1].args,
            (resource.RLIMIT_FSIZE, (32 * 1024, 32 * 1024)),
        )

    def test_uses_clean_child_environment(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "AFL_NO_UI": "1",
                "LD_PRELOAD": "/tmp/untrusted.so",
                "LD_LIBRARY_PATH": "/tmp/untrusted",
            },
        ):
            report, mocked_run = self.run_smoke_with_fake_process()

        self.assertTrue(report.passed, report.format())
        child_env = mocked_run.call_args_list[0].kwargs["env"]
        self.assertEqual(
            set(child_env),
            {"PATH", "LC_ALL", "KEKKAI_HARNESS_DIAGNOSTICS"},
        )
        self.assertEqual(child_env["LC_ALL"], "C")

    def test_refuses_temporary_directory_inside_repository(self) -> None:
        unsafe_temp = self.root / "unsafe-temp"
        unsafe_temp.mkdir()

        with (
            patch("engine.fuzzing.smoke.os.geteuid", return_value=1000),
            patch(
                "engine.fuzzing.smoke.tempfile.gettempdir",
                return_value=str(unsafe_temp),
            ),
            patch("engine.fuzzing.smoke.run_process_group") as process,
        ):
            with self.assertRaises(HarnessSmokeError):
                run_harness_smoke(self.config, self.root)

        process.assert_not_called()

    def test_unexpected_exit_status_fails_case(self) -> None:
        def failing_process(argv, **kwargs):
            kwargs["stdout"].write(b"")
            kwargs["stderr"].write(b"unexpected harness failure")
            return_code = 2 if Path(argv[1]).name == "valid.png" else (
                2 if Path(argv[1]).name == "missing-input.png" else 0
            )
            return SimpleNamespace(returncode=return_code)

        report, _ = self.run_smoke_with_fake_process(failing_process)

        self.assertFalse(report.passed)
        valid_result = next(
            result for result in report.results if result.name == "valid_png"
        )
        self.assertEqual(valid_result.status, "failed")
        self.assertEqual(valid_result.actual_exit_code, 2)

    def test_missing_required_seed_fails_report(self) -> None:
        (self.seed_dir / "adam7.png").unlink()

        report, mocked_run = self.run_smoke_with_fake_process()

        self.assertFalse(report.passed)
        adam7_result = next(
            result for result in report.results if result.name == "adam7_png"
        )
        self.assertEqual(adam7_result.status, "failed")
        self.assertEqual(mocked_run.call_count, 12)

    def test_timeout_fails_smoke_case(self) -> None:
        calls = 0

        def timeout_first_case(argv, **kwargs):
            nonlocal calls
            calls += 1

            if calls == 1:
                raise __import__("subprocess").TimeoutExpired(
                    cmd=argv,
                    timeout=5.0,
                )

            return self.fake_run(argv, **kwargs)

        report, _ = self.run_smoke_with_fake_process(timeout_first_case)

        self.assertFalse(report.passed)
        self.assertEqual(report.results[0].status, "failed")
        self.assertIn("timeout", report.results[0].message)

    def test_refuses_to_run_as_root(self) -> None:
        with (
            patch(
                "engine.fuzzing.smoke.os.geteuid",
                return_value=0,
            ),
            patch("engine.fuzzing.smoke.run_process_group") as mocked_run,
        ):
            with self.assertRaises(HarnessSmokeError):
                run_harness_smoke(self.config, self.root)

        mocked_run.assert_not_called()

    def test_rejects_invalid_timeout(self) -> None:
        with patch(
            "engine.fuzzing.smoke.os.geteuid",
            return_value=1000,
        ):
            with self.assertRaises(HarnessSmokeError):
                run_harness_smoke(
                    self.config,
                    self.root,
                    timeout_seconds=0,
                )

    def test_rejects_unsupported_target(self) -> None:
        target = replace(self.config.target, name="other-target")
        config = replace(self.config, target=target)

        with patch(
            "engine.fuzzing.smoke.os.geteuid",
            return_value=1000,
        ):
            with self.assertRaises(HarnessSmokeError):
                run_harness_smoke(config, self.root)


if __name__ == "__main__":
    unittest.main()
