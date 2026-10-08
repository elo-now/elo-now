#!/usr/bin/env python3
"""Loopback-only, unprivileged hosting administration UI and bounded job queue."""
import argparse
import fcntl
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from urllib.parse import urlsplit
import uuid

from schema import MAX_BODY, ValidationError, origin, public_configuration, validate_configuration

JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
STATIC = {"/admin/": ("index.html", "text/html; charset=utf-8"),
          "/admin/index.html": ("index.html", "text/html; charset=utf-8"),
          "/admin/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/admin/style.css": ("style.css", "text/css; charset=utf-8"),
          "/admin/en.json": ("en.json", "application/json; charset=utf-8")}
PUBLIC_JOB_ERRORS = {"Configuration could not be applied. Check the server configuration and try again.",
                     "The configuration request expired. Submit it again."}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("Duplicate configuration field.")
        result[key] = value
    return result


def decode(data):
    try:
        return json.loads(data, object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValidationError("Invalid JSON.")))
    except (ValueError, UnicodeError, RecursionError):
        raise ValidationError("Invalid JSON.") from None


def read_file(path, maximum=128 * 1024, *, private=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise OSError("Invalid file")
        if private and (info.st_uid not in (0, os.getuid()) or info.st_mode & 0o027):
            raise OSError("Invalid file permissions")
        with os.fdopen(fd, "rb", closefd=False) as file:
            result = file.read(maximum + 1)
        if len(result) > maximum:
            raise OSError("File too large")
        return result
    finally:
        os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Busy(Exception):
    pass


class AdminState:
    def __init__(self, root, static, config):
        self.root, self.static = Path(root), Path(static)
        if not isinstance(config, dict) or set(config) != {"role", "public_origin", "proxy_key", "related_admin_url"}:
            raise ValidationError("Invalid admin service configuration.")
        if config["role"] not in ("api", "witness"):
            raise ValidationError("Invalid admin role.")
        self.role = config["role"]
        self.origin = origin(config["public_origin"])
        self.proxy_key = config["proxy_key"]
        if not isinstance(self.proxy_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", self.proxy_key):
            raise ValidationError("Invalid proxy credential.")
        related = config["related_admin_url"]
        if related is not None:
            if not isinstance(related, str) or not related.endswith("/admin/"):
                raise ValidationError("Invalid related administration address.")
            origin(related[:-len("/admin/")])
        self.related = related
        self.csrf = secrets.token_urlsafe(32)
        for name in ("queue", "status"):
            path = self.root / name
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                raise ValidationError("Invalid admin data directory.")

    def job(self, identifier):
        if not JOB_ID.fullmatch(identifier):
            return None
        path = self.root / "status" / (identifier + ".json")
        try:
            saved = decode(read_file(path, 8192))
        except FileNotFoundError:
            try:
                pending = decode(read_file(self.root / "queue" / (identifier + ".json"), MAX_BODY + 1024))
            except FileNotFoundError:
                return None
            if isinstance(pending, dict) and pending.get("id") == identifier:
                return {"id": identifier, "status": "pending"}
            raise ValidationError("Invalid job state.")
        if not isinstance(saved, dict) or saved.get("id") != identifier or saved.get("status") not in ("pending", "succeeded", "failed"):
            raise ValidationError("Invalid job state.")
        result = {"id": identifier, "status": saved["status"]}
        if result["status"] == "failed":
            message = saved.get("error")
            result["error"] = message if isinstance(message, str) and message in PUBLIC_JOB_ERRORS else "Configuration could not be applied. Check the server configuration and try again."
        return result

    def enqueue(self, configuration):
        queue = self.root / "queue"
        lock_fd = os.open(queue / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        temporary = None
        try:
            info = os.fstat(lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
                raise OSError("Invalid queue lock")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy() from None
            count = 0
            for candidate in queue.iterdir():
                if candidate.name.endswith(".json") and JOB_ID.fullmatch(candidate.stem):
                    count += 1
                    if count > 1024:
                        raise Busy()
                    current = self.job(candidate.stem)
                    if current is None or current["status"] not in ("succeeded", "failed"):
                        raise Busy()
            identifier = uuid.uuid4().hex
            value = {"v": 1, "id": identifier, "role": self.role, "created_at": int(time.time()), "configuration": configuration}
            encoded = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            temporary = queue / ("." + identifier + ".tmp")
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(encoded)
                file.flush()
                os.fsync(file.fileno())
            # The exclusive destination is published only after the complete body is durable.
            destination = queue / (identifier + ".json")
            os.link(temporary, destination, follow_symlinks=False)
            temporary.unlink()
            temporary = None
            sync_directory(queue)
            return identifier
        finally:
            if temporary is not None:
                try:
                    temporary.unlink()
                except OSError:
                    pass
            os.close(lock_fd)

    def public_state(self):
        saved = decode(read_file(self.root / "state.json"))
        if not isinstance(saved, dict):
            raise ValidationError("Invalid admin state.")
        hosting = saved.get("hosting")
        if hosting is not None:
            if not isinstance(hosting, dict) or not isinstance(hosting.get("link"), str) or not hosting["link"].startswith("elo://hosting/v1#") or len(hosting["link"]) > 32768:
                raise ValidationError("Invalid hosting state.")
            qr = hosting.get("qr_url")
            if not isinstance(qr, str) or len(qr) > 2048 or not qr.startswith("/") or qr.startswith("//") or "\\" in qr or urlsplit(qr).fragment:
                raise ValidationError("Invalid hosting QR address.")
            revision = hosting.get("revision")
            if type(revision) is not int or not 1 <= revision <= 9007199254740991:
                raise ValidationError("Invalid hosting revision.")
            hosting = {"link": hosting["link"], "qr_url": qr, "revision": revision}
        return {"role": self.role, "csrf_token": self.csrf,
                "configuration": public_configuration(self.role, saved.get("configuration")),
                "hosting": hosting, "related_admin_url": self.related,
                "logs_available": (self.root / "diagnostics-read-key").is_file()}

    def logs(self, query):
        # This credential never enters the browser. The public proxy exposes only
        # the collector's exact POST route; all reads retain admin VPN and auth.
        key = read_file(self.root / "diagnostics-read-key", 128).decode("ascii").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", key):
            raise ValidationError("Invalid diagnostic reader configuration.")
        connection = http.client.HTTPConnection("127.0.0.1", 17930, timeout=5)
        try:
            connection.request("GET", "/reports" + ("?" + query if query else ""),
                               headers={"Authorization": "Bearer " + key})
            response = connection.getresponse()
            body = response.read(1024 * 1024 + 1)
            if response.status == 400:
                return 400, {"error": "Invalid log filters."}
            if response.status != 200 or len(body) > 1024 * 1024:
                raise OSError("Diagnostic reader unavailable")
            return 200, decode(body)
        finally:
            connection.close()


class HeaderReader:
    def __init__(self, reader):
        self.reader, self.remaining = reader, 16384

    def readline(self, maximum=-1):
        line = self.reader.readline(min(maximum if maximum >= 0 else 16385, self.remaining + 1))
        self.remaining -= len(line)
        if self.remaining < 0:
            raise http.client.HTTPException("Request headers too large")
        return line


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "elo-admin"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass  # Never log request paths, credentials or submitted configuration.

    def send_error(self, code, message=None, explain=None):
        self.reply(code, {"error": "Invalid HTTP request."})

    def reply(self, code, value=None, *, body=None, content_type="application/json; charset=utf-8"):
        if body is None:
            body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(body)

    def single_header(self, key):
        values = self.headers.get_all(key, [])
        return values[0] if len(values) == 1 else None

    def equal(self, actual, expected):
        return isinstance(actual, str) and actual.isascii() and hmac.compare_digest(actual, expected)

    def parse_request(self):
        reader = self.rfile
        self.rfile = HeaderReader(reader)
        try:
            parsed = super().parse_request()
        finally:
            self.rfile = reader
        if not parsed:
            return False
        if not self.equal(self.single_header("X-Elo-Admin-Proxy-Key"), self.server.state.proxy_key):
            self.reply(403, {"error": "Access denied."})
            return False
        if len(self.path) > 2048:
            self.reply(414, {"error": "Request address is too long."})
            return False
        return True

    def do_GET(self):
        try:
            path = self.path
            if path == "/admin/api/state":
                self.reply(200, self.server.state.public_state())
            elif urlsplit(path).path == "/admin/api/logs":
                status, value = self.server.state.logs(urlsplit(path).query)
                self.reply(status, value)
            elif path.startswith("/admin/api/jobs/") and JOB_ID.fullmatch(path[len("/admin/api/jobs/"):]):
                value = self.server.state.job(path[len("/admin/api/jobs/"):])
                self.reply(200 if value is not None else 404, value or {"error": "Job not found."})
            elif path in STATIC:
                name, content_type = STATIC[path]
                body = read_file(self.server.state.static / name, 512 * 1024, private=False)
                self.reply(200, body=body, content_type=content_type)
            else:
                self.reply(404, {"error": "Not found."})
        except (OSError, http.client.HTTPException, UnicodeError, ValidationError, KeyError, TypeError):
            self.reply(503, {"error": "Administration state is unavailable."})

    def do_POST(self):
        try:
            if self.path != "/admin/api/config":
                self.reply(404, {"error": "Not found."})
                return
            if not self.equal(self.single_header("Origin"), self.server.state.origin) or not self.equal(self.single_header("X-CSRF-Token"), self.server.state.csrf):
                self.reply(403, {"error": "Refresh the page before submitting changes."})
                return
            if self.headers.get_all("Transfer-Encoding") or self.single_header("Content-Type") not in ("application/json", "application/json; charset=utf-8"):
                self.reply(415, {"error": "A JSON request is required."})
                return
            length = self.single_header("Content-Length")
            if not isinstance(length, str) or not re.fullmatch(r"[0-9]{1,8}", length) or not 0 < int(length) <= MAX_BODY:
                self.reply(413, {"error": "Configuration request is too large or incomplete."})
                return
            body = self.rfile.read(int(length))
            if len(body) != int(length):
                self.reply(400, {"error": "Incomplete configuration request."})
                return
            configuration = validate_configuration(self.server.state.role, decode(body))
            identifier = self.server.state.enqueue(configuration)
            self.reply(202, {"id": identifier, "status": "pending"})
        except ValidationError as error:
            self.reply(400, {"error": str(error)})
        except Busy:
            self.reply(409, {"error": "Another configuration change is still pending."})
        except TimeoutError:
            self.reply(408, {"error": "Configuration request timed out."})
        except (OSError, KeyError, TypeError):
            self.reply(503, {"error": "Configuration could not be queued. Try again."})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    allow_reuse_address = True

    def __init__(self, address, state):
        if address[0] != "127.0.0.1":
            raise ValidationError("Administration must bind to loopback.")
        self.state = state
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # Avoid traceback/request disclosure; HTTP callers receive fixed errors.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/srv/elo-admin"))
    parser.add_argument("--static", type=Path, default=Path(__file__).with_name("static"))
    parser.add_argument("--port", type=int, default=17910)
    args = parser.parse_args()
    if os.getuid() == 0:
        parser.error("Run the administration server as its unprivileged service user.")
    try:
        config = decode(read_file(args.root / "config.json", 8192))
        state = AdminState(args.root, args.static, config)
        Server(("127.0.0.1", args.port), state).serve_forever(poll_interval=0.25)
    except (OSError, ValidationError):
        raise SystemExit("Administration service configuration is unavailable.") from None


if __name__ == "__main__":
    main()
