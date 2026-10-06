#!/usr/bin/env python3
"""Install a final Windows/Linux package and verify its visible startup, without a profile."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(args: list[str], **kwargs) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=180, **kwargs).strip()


def final_installer(bundle: Path, suffix: str, version: str) -> Path:
    files = list(bundle.rglob(f"*{suffix}"))
    if len(files) != 1 or not files[0].is_file() or files[0].is_symlink() or f"_{version}_" not in files[0].name:
        raise RuntimeError("Expected one final installer matching the release version")
    return files[0].resolve()


def windows_api():
    from ctypes import wintypes
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.GetProcessWindowStation.restype = wintypes.HANDLE
    user.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    return user


def require_display(platform: str) -> None:
    if platform == "linux":
        if not os.environ.get("DISPLAY"):
            raise RuntimeError("A graphical display is required; run this smoke under xvfb-run and dbus-run-session")
        run(["xdotool", "getdisplaygeometry"])
    elif platform == "win32":
        from ctypes import wintypes
        class Flags(ctypes.Structure):
            _fields_ = [("inherit", wintypes.BOOL), ("reserved", wintypes.BOOL), ("flags", wintypes.DWORD)]
        user = windows_api()
        flags, needed = Flags(), wintypes.DWORD()
        if not user.GetUserObjectInformationW(user.GetProcessWindowStation(), 1, ctypes.byref(flags),
                                              ctypes.sizeof(flags), ctypes.byref(needed)) or not flags.flags & 1:
            raise RuntimeError("Windows runner has no interactive window station; startup smoke cannot pass")
    else:
        raise RuntimeError("Installed startup smoke supports Windows and Linux only")


def visible_window(pid: int, platform: str) -> bool:
    if platform == "linux":
        result = subprocess.run(["xdotool", "search", "--onlyvisible", "--pid", str(pid), "--name", "^elo\\.now$"],
                                capture_output=True, text=True, timeout=5)
        if result.returncode not in (0, 1):
            raise RuntimeError("Unable to inspect the installed application's graphical window")
        return result.returncode == 0 and bool(result.stdout.strip())
    from ctypes import wintypes
    user, found = windows_api(), []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]

    @callback_type
    def inspect(window, _):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == pid and user.IsWindowVisible(window):
            title = ctypes.create_unicode_buffer(256)
            user.GetWindowTextW(window, title, len(title))
            if title.value == "elo.now":
                found.append(True)
        return True

    if not user.EnumWindows(inspect, 0):
        raise RuntimeError("Unable to enumerate Windows application windows")
    return bool(found)


def wait_for_startup(process, window_visible, *, clock=time.monotonic, sleep=time.sleep) -> float:
    started, first_visible = clock(), None
    while clock() - started < 45:
        if process.poll() is not None:
            raise RuntimeError(f"Installed application exited during startup (exit code {process.returncode})")
        if window_visible():
            if first_visible is None:
                first_visible = clock()
            if clock() - first_visible >= 10:
                return clock() - started
        else:
            first_visible = None
        sleep(0.5)
    raise RuntimeError("Installed application did not keep a visible window for 10 seconds within 45 seconds")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"status": "failed", "platform": sys.platform, "version": args.version,
              "scope": "Installed application's visible startup; no login, network or messaging claim"}
    process = None
    try:
        require_display(sys.platform)
        installer = final_installer(args.bundle, ".deb" if sys.platform == "linux" else ".exe", args.version)
        report["installer"] = installer.name
        if sys.platform == "linux":
            package = run(["dpkg-deb", "-f", str(installer), "Package"])
            if run(["dpkg-deb", "-f", str(installer), "Version"]) != args.version:
                raise RuntimeError("Debian installer metadata does not match the requested version")
            run(["sudo", "apt-get", "install", "-y", str(installer)])
            binaries = [Path(name) for name in run(["dpkg-query", "-L", package]).splitlines()
                        if name.startswith("/usr/bin/") and Path(name).is_file() and os.access(name, os.X_OK)]
        else:
            destination = Path(os.environ["RUNNER_TEMP"]) / "elo-installed-smoke"
            if destination.exists():
                raise RuntimeError("Smoke installation directory must be new")
            # NSIS requires /D to be the last argument. The official runner's temp path has no spaces.
            if " " in str(destination):
                raise RuntimeError("NSIS smoke installation requires a destination without spaces")
            run([str(installer), "/S", f"/D={destination}"])
            binaries = list(destination.glob("elo*.exe"))
        if len(binaries) != 1:
            raise RuntimeError("Expected exactly one installed elo application executable")
        binary = binaries[0].resolve()
        report["executable"] = str(binary)
        with args.report.with_suffix(".log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen([str(binary)], stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=sys.platform == "linux")
            report["startup_seconds"] = round(wait_for_startup(process, lambda: visible_window(process.pid, sys.platform)), 2)
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        if process is not None:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=10)
            else:
                import signal
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=10)
                except ProcessLookupError:
                    pass
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
