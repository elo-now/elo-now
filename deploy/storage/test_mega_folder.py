"""Offline security checks for the private MEGAcmd adapter boundary."""

import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "mega_folder_adapter", Path(__file__).with_name("mega_folder.py")
)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)

FOLDER = "https://mega.nz/folder/abcdefgh#" + "A" * 22
AUTH = "B" * 32


def request(op="delete", **values):
    return {
        "op": op,
        "folder_link": FOLDER,
        "write_auth": AUTH,
        "space": "a" * 64,
        "object": "b" * 64,
        **values,
    }


class PrivateSocket:
    """A fragmented socket stream; this class never opens an actual socket."""

    def __init__(self, payload, fragment=3):
        self.payload = payload
        self.fragment = fragment
        self.sent = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def settimeout(self, seconds):
        self.timeout = seconds

    def connect(self, path):
        self.path = path

    def sendall(self, payload):
        self.sent = payload

    def recv(self, requested):
        size = min(requested, self.fragment)
        chunk, self.payload = self.payload[:size], self.payload[size:]
        return chunk


class ValidationTests(unittest.TestCase):
    def test_invalid_json_types_and_unknown_keys_never_start_a_provider(self):
        invalid = [None, False, 3, [], "request", request(unknown="value")]
        for field in ["folder_link", "write_auth", "space", "object", "data"]:
            for value in [None, False, 42, [], {}]:
                invalid.append(request("put", **{field: value}))
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                stdin = Mock(buffer=io.BytesIO(json.dumps(candidate).encode()))
                output = io.StringIO()
                with patch.object(adapter.sys, "stdin", stdin), patch.object(
                    adapter.subprocess, "Popen"
                ) as start, patch.object(adapter.signal, "signal"), patch.object(
                    adapter.signal, "alarm"
                ), patch.object(adapter.os, "umask"), contextlib.redirect_stdout(output):
                    adapter.main()
                result = json.loads(output.getvalue())
                self.assertFalse(result["ok"])
                self.assertNotIn(FOLDER, output.getvalue())
                self.assertNotIn(AUTH, output.getvalue())
                start.assert_not_called()

    def test_untrusted_commands_and_paths_never_start_a_provider(self):
        invalid = [
            request(op="logout"),
            request(op="put", command="rm -rf /"),
            request(folder_link="http://127.0.0.1/folder/abcdefgh#" + "A" * 22),
            request(folder_link=FOLDER + " --auth-key=other"),
            request(folder_link=FOLDER + "\nlogout"),
            request(write_auth=AUTH + "; id"),
            request(space="../outside"),
            request(object="/etc/passwd"),
            request(object="b" * 64 + "\nrm /"),
        ]
        with patch.object(adapter, "runtime_root") as runtime, patch.object(
            adapter.subprocess, "Popen"
        ) as start:
            for candidate in invalid:
                with self.subTest(candidate=candidate):
                    with self.assertRaises(adapter.StorageError):
                        adapter.operate(candidate)
            runtime.assert_not_called()
            start.assert_not_called()

    def test_payload_decoding_is_strict_and_bounded(self):
        with patch.object(adapter, "MAX_BYTES", 4):
            self.assertEqual(
                adapter.validate(request("put", data=base64.b64encode(b"1234").decode())),
                b"1234",
            )
            for value in ["%%%", "MTIz\nNA==", base64.b64encode(b"12345").decode()]:
                with self.subTest(value=value):
                    with self.assertRaises(adapter.StorageError):
                        adapter.validate(request("put", data=value))

    def test_main_never_returns_exception_details_or_credentials(self):
        stdin = Mock(buffer=io.BytesIO(json.dumps(request()).encode()))
        output = io.StringIO()
        with patch.object(adapter.sys, "stdin", stdin), patch.object(
            adapter, "operate", side_effect=RuntimeError(FOLDER + AUTH)
        ), patch.object(adapter.signal, "signal"), patch.object(
            adapter.signal, "alarm"
        ), patch.object(adapter.os, "umask"), contextlib.redirect_stdout(output):
            adapter.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result, {"ok": False, "error": "provider_unavailable"})
        self.assertNotIn(FOLDER, output.getvalue())
        self.assertNotIn(AUTH, output.getvalue())


class IpcTests(unittest.TestCase):
    def test_exact_handles_fragmentation_and_rejects_truncation(self):
        self.assertEqual(adapter.exact(PrivateSocket(b"12345"), 5), b"12345")
        with self.assertRaisesRegex(adapter.StorageError, "provider_protocol"):
            adapter.exact(PrivateSocket(b"12"), 3)

    def test_partial_output_and_final_output_do_not_escape_the_private_socket(self):
        private_output = (FOLDER + AUTH).encode()
        payload = (
            struct.pack("=i", -62)
            + struct.pack("@N", len(private_output))
            + private_output
            + struct.pack("=i", -63)
            + struct.pack("@N", 0)
            + struct.pack("=i", 0)
            + private_output
        )
        sock = PrivateSocket(payload)
        output = io.StringIO()
        with patch.object(adapter.socket, "socket", return_value=sock), contextlib.redirect_stdout(output):
            self.assertEqual(adapter.execute(Path("/private/socket"), "pwd"), 0)
        self.assertEqual(sock.sent, b"pwd")
        self.assertEqual(output.getvalue(), "")

    def test_declared_output_size_is_rejected_before_reading_its_body(self):
        sock = PrivateSocket(
            struct.pack("=i", -62) + struct.pack("@N", adapter.MAX_REPLY + 1)
        )
        with patch.object(adapter.socket, "socket", return_value=sock):
            with self.assertRaisesRegex(adapter.StorageError, "provider_output_limit"):
                adapter.execute(Path("/private/socket"), "pwd")

    def test_final_output_limit_and_interactive_prompts_fail_closed(self):
        with patch.object(adapter, "MAX_REPLY", 4):
            sock = PrivateSocket(struct.pack("=i", 0) + b"12345")
            with patch.object(adapter.socket, "socket", return_value=sock):
                with self.assertRaisesRegex(adapter.StorageError, "provider_output_limit"):
                    adapter.execute(Path("/private/socket"), "pwd")
        for code in [-60, -61]:
            with self.subTest(code=code), patch.object(
                adapter.socket, "socket", return_value=PrivateSocket(struct.pack("=i", code))
            ):
                with self.assertRaisesRegex(adapter.StorageError, "provider_interaction_required"):
                    adapter.execute(Path("/private/socket"), "pwd")

    def test_provider_errors_expose_only_a_fixed_class(self):
        for code, expected in [(-53, "not_found"), (-9, "not_found"), (-999, "provider_rejected")]:
            with self.subTest(code=code), patch.object(adapter, "execute", return_value=code):
                with self.assertRaisesRegex(adapter.StorageError, "^" + expected + "$"):
                    adapter.checked(Path("/private/socket"), "pwd")
        with patch.object(adapter, "execute", return_value=-53):
            adapter.checked(Path("/private/socket"), "rm -f /object", (0, -53, -9))


class RuntimeTests(unittest.TestCase):
    def runtime(self, base, *, symlink=False, mode=0o700, filesystem="tmpfs"):
        base = Path(base).resolve()
        actual = base / "persistent"
        actual.mkdir(mode=0o700)
        visible = base / "runtime"
        if symlink:
            visible.symlink_to(actual, target_is_directory=True)
        else:
            visible.mkdir(mode=0o700)
        root = visible / "mega"
        root.mkdir(mode=mode)
        root.chmod(mode)
        mounts = base / "mounts"
        mounts.write_text(f"rootfs / rootfs rw 0 0\ntmpfs {visible} {filesystem} rw 0 0\n")

        def path(value):
            if value == "/run/elo-storage/mega":
                return root
            if value == "/proc/mounts":
                return mounts
            return Path(value)

        return root, path

    def test_persistent_or_other_user_readable_runtime_is_rejected(self):
        for mode, filesystem in [(0o755, "tmpfs"), (0o700, "ext4")]:
            with self.subTest(mode=mode, filesystem=filesystem), tempfile.TemporaryDirectory() as base:
                _, mapped_path = self.runtime(base, mode=mode, filesystem=filesystem)
                with patch.object(adapter, "Path", side_effect=mapped_path):
                    with self.assertRaises(adapter.StorageError):
                        adapter.runtime_root()

    def test_private_runtime_on_tmpfs_is_accepted(self):
        with tempfile.TemporaryDirectory() as base:
            root, mapped_path = self.runtime(base)
            with patch.object(adapter, "Path", side_effect=mapped_path):
                self.assertEqual(adapter.runtime_root(), root)

    def test_a_symlink_parent_cannot_disguise_persistent_session_storage_as_tmpfs(self):
        with tempfile.TemporaryDirectory() as base:
            _, mapped_path = self.runtime(base, symlink=True)
            with patch.object(adapter, "Path", side_effect=mapped_path):
                with self.assertRaises(adapter.StorageError):
                    adapter.runtime_root()


class CleanupTests(unittest.TestCase):
    @contextlib.contextmanager
    def provider(self, *, poll=None, timeout=False, exited_during_kill=False):
        # Keep the fake socket path below the adapter's Unix path length limit.
        with tempfile.TemporaryDirectory(prefix="mega-test-", dir="/tmp") as base:
            root = Path(base)
            daemon = Mock(pid=987654, poll=Mock(return_value=poll))
            if timeout:
                daemon.wait.side_effect = [subprocess.TimeoutExpired("provider", 3), 0]

            def start(_args, **kwargs):
                home = Path(kwargs["env"]["HOME"])
                (home / ".megaCmd" / "megacmd.socket").touch()
                (home / ".megaCmd" / "private-session").write_text(AUTH)
                return daemon

            with patch.object(adapter, "runtime_root", return_value=root), patch.object(
                adapter.subprocess, "Popen", side_effect=start
            ) as spawn, patch.object(adapter.os, "killpg") as kill:
                if exited_during_kill:
                    kill.side_effect = ProcessLookupError()
                yield root, daemon, spawn, kill

    def test_provider_failure_terminates_process_and_removes_session_cache(self):
        with self.provider() as (root, daemon, spawn, kill), patch.object(
            adapter, "checked", side_effect=adapter.StorageError("provider_rejected")
        ):
            with self.assertRaisesRegex(adapter.StorageError, "provider_rejected"):
                adapter.operate(request())
            self.assertEqual(list(root.iterdir()), [])
            kill.assert_any_call(daemon.pid, signal.SIGTERM)
            kill.assert_any_call(daemon.pid, signal.SIGKILL)
            self.assertTrue(daemon.wait.called)
            self.assertTrue(all(call.kwargs.get("timeout", 999) <= 3 for call in daemon.wait.call_args_list))
            args, kwargs = spawn.call_args
            self.assertNotIn(AUTH, str(args) + str(kwargs["env"]))
            self.assertNotIn(FOLDER, str(args) + str(kwargs["env"]))
            self.assertTrue(kwargs["start_new_session"])
            self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)

    def test_stuck_provider_is_killed_before_the_session_cache_is_removed(self):
        with self.provider(timeout=True) as (root, daemon, _spawn, kill), patch.object(adapter, "checked"):
            self.assertEqual(adapter.operate(request()), {"ok": True})
            self.assertEqual([call.args for call in kill.call_args_list], [
                (daemon.pid, signal.SIGTERM), (daemon.pid, signal.SIGKILL),
            ])
            self.assertEqual(list(root.iterdir()), [])

    def test_descendants_are_terminated_even_if_the_group_leader_has_exited(self):
        with self.provider(poll=0) as (root, daemon, _spawn, kill), patch.object(adapter, "checked"):
            self.assertEqual(adapter.operate(request()), {"ok": True})
            kill.assert_any_call(daemon.pid, signal.SIGTERM)
            self.assertEqual(list(root.iterdir()), [])

    def test_a_natural_exit_between_poll_and_kill_does_not_replace_success(self):
        with self.provider(exited_during_kill=True) as (root, _daemon, _spawn, _kill), patch.object(adapter, "checked"):
            self.assertEqual(adapter.operate(request()), {"ok": True})
            self.assertEqual(list(root.iterdir()), [])

    def test_probe_mismatch_is_rejected_and_the_remote_probe_is_removed(self):
        commands = []

        def checked(_ipc, command, _allowed=(0,)):
            commands.append(command)
            if command.startswith("get "):
                Path(command.split()[-1]).write_bytes(b"different file")

        with self.provider() as (root, _daemon, _spawn, _kill), patch.object(
            adapter, "checked", side_effect=checked
        ):
            with self.assertRaisesRegex(adapter.StorageError, "provider_integrity"):
                adapter.operate(request("probe"))
            self.assertTrue(commands[-1].startswith("rm -f /elo-probe-"))
            self.assertEqual(list(root.iterdir()), [])

    def test_downloaded_symlink_or_oversized_file_is_not_returned(self):
        for mode in ["symlink", "oversized"]:
            with self.subTest(mode=mode), self.provider() as (root, _daemon, _spawn, _kill):
                outside = root / "outside"
                outside.write_text("must not leave the machine")

                def checked(_ipc, command, _allowed=(0,)):
                    if not command.startswith("get "):
                        return
                    target = Path(command.split()[-1])
                    if mode == "symlink":
                        target.symlink_to(outside)
                    else:
                        target.write_bytes(b"12345")

                with patch.object(adapter, "checked", side_effect=checked), patch.object(adapter, "MAX_BYTES", 4):
                    with self.assertRaises(adapter.StorageError):
                        adapter.operate(request("get"))
                self.assertEqual(list(root.iterdir()), [outside])


if __name__ == "__main__":
    unittest.main()
