#!/usr/bin/env python3
"""Exercise locally built Linux images using disposable synthetic state only.

No pulls, public ports, TLS, provider requests, Docker socket mounts or existing
application data. Cleanup names only resources created by this invocation.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent


def run(arguments, data=None, check=True, timeout=45):
    return subprocess.run(["docker", *arguments], input=data, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=check, timeout=timeout)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Smoke:
    def __init__(self, version, caddy_image=None, media_image=None, turn_image=None):
        self.version = version
        self.caddy_image = caddy_image
        self.media_image = media_image
        self.turn_image = turn_image
        self.prefix = "elo-smoke-" + uuid.uuid4().hex[:12]
        self.containers = []
        self.volumes = []
        self.network = None
        self.images = {role: f"elo-{role}:{version}" for role in ("api", "witness", "storage", "wake", "calls", "storage-mega")}

    def cleanup(self):
        errors = []
        commands = [["rm", "--force", name] for name in dict.fromkeys(reversed(self.containers))]
        commands.extend(["volume", "rm", name] for name in reversed(self.volumes))
        if self.network:
            commands.append(["network", "rm", self.network])
        for command in commands:
            try:
                result = run(command, check=False, timeout=15)
                # --rm helpers and deliberately recreated containers may already be gone.
                missing = any(value in result.stderr.lower() for value in ("no such container", "no such volume", "no such network"))
                if result.returncode != 0 and not missing:
                    errors.append(command[-1] + ": " + result.stderr.strip()[-500:])
            except (subprocess.TimeoutExpired, OSError) as error:
                errors.append(command[-1] + ": " + str(error))
        return errors

    def volume(self, role):
        name = self.prefix + "-" + role
        self.volumes.append(name)
        run(["volume", "create", "--label", "elo.test=container-smoke", name])
        return name

    def options(self, uid, network="none"):
        return ["--pull", "never", "--network", network, "--read-only", "--user", f"{uid}:{uid}",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "128",
                "--memory", "512m", "--memory-swap", "512m", "--ulimit", "core=0",
                "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid={uid},gid={uid}"]

    def helper(self, arguments, mounts=(), data=None, uid=0, network="none"):
        name = self.prefix + "-helper-" + uuid.uuid4().hex[:6]
        self.containers.append(name)
        command = ["run", "--rm", "--name", name, *self.options(uid, network)]
        if data is not None:
            command.append("--interactive")
        for mount in mounts:
            command.extend(["--mount", mount])
        # Initializers need these capabilities for dedicated numeric owners.
        if uid == 0:
            command.extend(["--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER"])
        command.extend([self.images["api"], *arguments])
        return run(command, data=data)

    def start(self, role, volume, namespace):
        uid = {"api": 21001, "witness": 21002, "storage": 21003, "wake": 21006, "calls": 21007}[role]
        name = self.prefix + "-" + role
        self.containers.append(name)
        command = ["run", "--detach", "--name", name, *self.options(uid, namespace),
                   "--init", "--stop-signal", "SIGINT", "--stop-timeout", "30",
                   "--mount", f"type=volume,src={volume},dst=/etc/elo/{role},volume-subpath=state/{role}/config,readonly",
                   "--mount", f"type=volume,src={volume},dst=/var/lib/elo-{role},volume-subpath=state/{role}/data"]
        if role == "witness":
            command.extend(["--tmpfs", "/run/elo-witness:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=21002,gid=21002"])
        if role == "storage":
            command.extend(["--tmpfs", "/run/elo-storage:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=21003,gid=21003"])
        command.append(self.images[role])
        run(command)
        return name

    def status(self, namespace, url):
        result = run(["exec", namespace.removeprefix("container:"), "curl", "--silent", "--max-time", "3",
                      "--output", "/dev/null", "--write-out", "%{http_code}", url], timeout=10)
        return result.stdout

    def wait_healthy(self, name, namespace, url, expected="200"):
        last = "not started"
        for _ in range(30):
            state = run(["inspect", "--format", "{{.State.Running}}", name]).stdout.strip()
            if state != "true":
                # Synthetic configuration only; no provider credentials or user data exist here.
                logs = run(["logs", "--tail", "30", name], check=False)
                raise RuntimeError(f"{name} exited: {logs.stdout}{logs.stderr}")
            try:
                last = self.status(namespace, url)
            except subprocess.CalledProcessError:
                last = "connection unavailable"
            if last == expected:
                return
            time.sleep(0.2)
        raise RuntimeError(f"{name} health expected {expected}, received {last}")

    def check_proxy(self, api_volume, witness_volume, namespace, tools_mount):
        """Exercise the generated routes over isolated HTTP, without DNS or TLS."""
        run(["image", "inspect", self.caddy_image])
        publish = """import importlib.util,json,pathlib
spec=importlib.util.spec_from_file_location('public_export','/tools/export.py')
export=importlib.util.module_from_spec(spec); spec.loader.exec_module(export)
root=pathlib.Path('/srv/state'); data=root/'export/data'
value=json.loads((data/'hosting-profile.json').read_text())
export.provision.stable(root/'public/hosting-profile.html',export.hosting_page(value['link']),0,0o644)
export.provision.stable(root/'public/hosting-qr.svg',(data/'hosting-qr.svg').read_bytes(),0,0o644)
export.provision.stable(root/'proxy/config/Caddyfile.smoke',export.provision.proxy_config('api','http://127.0.0.1:18080',False,True,True),21004)
"""
        self.helper(["python3", "-B", "-c", publish],
                    mounts=(tools_mount, f"type=volume,src={api_volume},dst=/srv"))
        configure_witness = """import importlib.util,pathlib
spec=importlib.util.spec_from_file_location('provision','/tools/init.py')
provision=importlib.util.module_from_spec(spec); spec.loader.exec_module(provision)
provision.stable(pathlib.Path('/srv/state/proxy/config/Caddyfile.smoke'),provision.proxy_config('witness','http://127.0.0.1:18081',True),21004)
"""
        self.helper(["python3", "-B", "-c", configure_witness],
                    mounts=(tools_mount, f"type=volume,src={witness_volume},dst=/srv"))
        for role, volume in (("api", api_volume), ("witness", witness_volume)):
            name = self.prefix + "-proxy-" + role
            self.containers.append(name)
            command = ["run", "--detach", "--name", name, *self.options(21004, namespace),
                       "--cap-add", "NET_BIND_SERVICE", "--env", "XDG_DATA_HOME=/data", "--env", "XDG_CONFIG_HOME=/tmp/config",
                       "--tmpfs", "/data:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=21004,gid=21004",
                       "--mount", f"type=volume,src={volume},dst=/etc/caddy,volume-subpath=state/proxy/config,readonly"]
            if role == "api":
                command.extend(["--mount", f"type=volume,src={volume},dst=/srv/elo-public,volume-subpath=state/public,readonly"])
            command.extend([self.caddy_image, "caddy", "run", "--config", "/etc/caddy/Caddyfile.smoke", "--adapter", "caddyfile"])
            run(command)
            if role == "api":
                self.wait_healthy(name, namespace, "http://127.0.0.1:18080/hosting/")
            else:
                self.wait_healthy(name, namespace, "http://127.0.0.1:18081/readyz", "404")
        keeper = namespace.removeprefix("container:")
        html = run(["exec", keeper, "curl", "--fail", "--silent", "--max-time", "3", "http://127.0.0.1:18080/hosting/"]).stdout
        require("elo://hosting/v1#" in html and 'src="hosting-qr.svg"' in html and "Copy link" in html,
                "Public hosting page is missing the real link, local QR or copy instructions.")
        svg = run(["exec", keeper, "curl", "--fail", "--silent", "--max-time", "3", "http://127.0.0.1:18080/hosting/hosting-qr.svg"]).stdout
        require("<svg" in svg and "</svg>" in svg, "Public hosting QR route failed.")
        require(self.status(namespace, "http://127.0.0.1:18080/hosting") == "308", "Hosting directory redirect failed.")
        require(self.status(namespace, "http://127.0.0.1:18080/spaces/v1/health") == "200", "API reverse proxy failed.")
        require(self.status(namespace, "http://127.0.0.1:18080/calls/v1/health") == "204", "Call reverse proxy failed.")
        require(self.status(namespace, "http://127.0.0.1:18080/wake/health") == "204", "Wake reverse proxy failed.")
        for path in ("/internal/calls/admission", "/internal/calls/event", "/media/twirp", "/media/twirp/livekit.RoomService/CreateRoom"):
            require(self.status(namespace, "http://127.0.0.1:18080" + path) == "404", "Proxy exposed a private media route.")
        for path in ("/readyz", "/livez", "/health", "/storage/v1/health"):
            require(self.status(namespace, "http://127.0.0.1:18081" + path) == "404", "Proxy exposed a private health route.")
        print("PASS: isolated Caddy serves the exported page/QR and API; witness private health routes stay hidden", flush=True)

    def check_media(self, api_volume, namespace, tools_mount):
        if not self.media_image or not self.turn_image:
            return
        for image in (self.media_image, self.turn_image):
            run(["image", "inspect", image])
        keeper = namespace.removeprefix("container:")
        interfaces = json.loads(run(["inspect", "--format", "{{json .NetworkSettings.Networks}}", keeper]).stdout)
        address = interfaces[self.network]["IPAddress"]
        # Substitute only the synthetic deployment's fictitious public address.
        # Containers share one isolated namespace and send no peer media traffic.
        code = """import pathlib,sys
root=pathlib.Path('/srv/state')
for name in ('media/config/livekit.yaml','turn/config/turnserver.conf'):
 p=root/name; s=p.read_text(); assert '8.8.8.8' in s; p.write_text(s.replace('8.8.8.8',sys.argv[1]))
"""
        self.helper(["python3", "-c", code, address], mounts=(f"type=volume,src={api_volume},dst=/srv",))
        for role, uid, image, command in (
            ("media", 21008, self.media_image, ["--config", "/etc/elo/media/livekit.yaml"]),
            ("turn", 21009, self.turn_image, ["-c", "/etc/elo/turn/turnserver.conf"]),
        ):
            name = self.prefix + "-" + role
            self.containers.append(name)
            arguments = ["run", "--detach", "--name", name, *self.options(uid, namespace),
                         "--mount", f"type=volume,src={api_volume},dst=/etc/elo/{role},volume-subpath=state/{role}/config,readonly"]
            if role == "turn":
                arguments += ["--cap-add", "NET_BIND_SERVICE", "--tmpfs",
                              "/var/lib/coturn:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=21009,gid=21009",
                              "--entrypoint", "turnserver"]
            run([*arguments, image, *command])
            if role == "media":
                self.wait_healthy(name, namespace, "http://127.0.0.1:7880/", "200")
        # Only synthetic keys exist in this private volume; do not print them.
        turn_test = """import importlib.util,json,pathlib,sys,time
spec=importlib.util.spec_from_file_location('turn_smoke','/tools/turn_smoke.py')
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
secret=json.loads(pathlib.Path('/srv/state/calls/config/config.json').read_text())['media']['turn_secret']
for attempt in range(15):
 try:
  module.allocate(sys.argv[1],secret); break
 except (TimeoutError,ConnectionError,OSError):
  if attempt == 14: raise
  time.sleep(.2)
"""
        result = self.helper(["python3", "-B", "-c", turn_test, address],
                             mounts=(tools_mount, f"type=volume,src={api_volume},dst=/srv,readonly"), network=namespace)
        require("PASS: TURN" in result.stdout, "TURN allocation probe did not complete.")
        forbidden = run(["exec", keeper, "curl", "--silent", "--max-time", "3", "--output", "/dev/null",
                         "--write-out", "%{http_code}", "--header", "Content-Type: application/json", "--data", "{}",
                         "http://127.0.0.1:7880/twirp/livekit.RoomService/ListRooms"]).stdout
        require(forbidden == "401",
                "Unauthenticated media administration was exposed.")
        sockets = """from pathlib import Path
def bound(protocol,port):
 found=[]
 for suffix in ('','6'):
  p=Path('/proc/net/'+protocol+suffix)
  if not p.exists(): continue
  for row in p.read_text().splitlines()[1:]:
   host,value=row.split()[1].split(':')
   if int(value,16)==port: found.append(host)
 return found
for protocol,port in (('tcp',7881),('udp',7882)):
 addresses=bound(protocol,port)
 assert addresses and any(a not in ('0100007F','00000000000000000000000001000000') for a in addresses), (protocol,port,addresses)
assert bound('tcp',7880)==['0100007F'], 'LiveKit HTTP escaped loopback'
print('Public ICE bindings and private LiveKit HTTP verified')
"""
        result = self.helper(["python3", "-c", sockets], network=namespace)
        require("Public ICE bindings" in result.stdout, "ICE socket verification failed.")
        print("PASS: non-root LiveKit startup and authenticated TURN allocation; no media or external peer traffic", flush=True)

    def check_mega_runtime(self):
        name = self.prefix + "-mega-runtime"
        self.containers.append(name)
        script = """import importlib.util,os,pathlib,signal,subprocess,tempfile,time
spec=importlib.util.spec_from_file_location('mega','/opt/elo/storage/mega_folder.py')
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
root=module.runtime_root()
with tempfile.TemporaryDirectory(prefix='op-',dir=root) as temporary:
 home=pathlib.Path(temporary); (home/'.megaCmd').mkdir(mode=0o700)
 process=subprocess.Popen(['/usr/bin/mega-cmd-server','--debug=0'],env={'HOME':temporary,'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 try:
  ipc=home/'.megaCmd/megacmd.socket'
  for _ in range(100):
   if ipc.exists(): break
   assert process.poll() is None
   time.sleep(.05)
  assert ipc.exists()
  assert module.execute(ipc,'version') == 0
 finally:
  os.killpg(process.pid,signal.SIGTERM)
  try: process.wait(timeout=3)
  except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); process.wait(timeout=3)
print('MEGAcmd private IPC and volatile runtime ready')
"""
        result = run(["run", "--rm", "--name", name, *self.options(21003),
                      "--tmpfs", "/run/elo-storage:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=21003,gid=21003",
                      self.images["storage-mega"], "python3", "-B", "-c", script])
        require("private IPC and volatile runtime ready" in result.stdout, "MEGA private helper failed.")
        print("PASS: MEGAcmd starts unprivileged with private IPC on tmpfs; no login or provider traffic", flush=True)

    def execute(self):
        for role, image in self.images.items():
            run(["image", "inspect", image])
            name = self.prefix + "-help-" + role
            self.containers.append(name)
            help_result = run(["run", "--rm", "--name", name, *self.options(21001), image,
                               {"api": "elo-team", "witness": "elo-witness", "storage": "elo-storage", "storage-mega": "elo-storage",
                                "wake": "elo-wake", "calls": "elo-call-service"}[role], "--help"])
            require("Usage:" in help_result.stdout, f"Missing {role} CLI help.")
        print("PASS: all six Linux image CLIs execute", flush=True)
        self.check_mega_runtime()

        api_volume, witness_volume = self.volume("api-state"), self.volume("witness-state")
        tools_mount = f"type=bind,src={HERE},dst=/tools,readonly"
        witness_mount = f"type=volume,src={witness_volume},dst=/srv"
        api_mount = f"type=volume,src={api_volume},dst=/srv"
        initialized = self.helper(["python3", "-B", "/tools/init.py", "witness", "--state", "/srv/state",
                                   "--origin", "https://witness.example.test", "--version", self.version, "--with-storage"],
                                  mounts=(tools_mount, witness_mount))
        pin = json.loads(initialized.stdout)["witness"]
        api_init = ["python3", "-B", "/tools/init.py", "api", "--state", "/srv/state",
                    "--origin", "https://api.example.test", "--version", self.version,
                    "--witness-pin", "/tmp/witness-pin.json", "--name", "Synthetic container test",
                    "--storage-url", "https://witness.example.test/storage/v1", "--creator", "11" * 32,
                    "--firebase", "/tmp/firebase.json", "--call-ip", "8.8.8.8"]
        code = """import json,pathlib,subprocess,sys,os
pathlib.Path('/tmp/witness-pin.json').write_text(sys.stdin.read())
key=subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048'],capture_output=True,check=True).stdout.decode()
firebase={'type':'service_account','project_id':'elo-synthetic','client_email':'test@elo-synthetic.iam.gserviceaccount.com','private_key_id':'synthetic','private_key':key,'token_uri':'https://oauth2.googleapis.com/token'}
p=pathlib.Path('/tmp/firebase.json'); p.write_text(json.dumps(firebase)); p.chmod(0o600)
subprocess.run(sys.argv[1:],check=True)
"""
        self.helper(["python3", "-c", code, *api_init], mounts=(tools_mount, api_mount), data=json.dumps(pin))
        self.helper(["python3", "-c", "import json,pathlib; p=json.loads(pathlib.Path('/srv/state/export/config/manifest-input.json').read_text()); assert p['name']=='Synthetic container test'"], mounts=(api_mount,))
        print("PASS: Linux root initializer provisions distinct non-root service state", flush=True)

        self.network = self.prefix + "-network"
        run(["network", "create", "--internal", "--label", "elo.test=container-smoke", self.network])
        keeper = self.prefix + "-namespace"
        self.containers.append(keeper)
        run(["run", "--detach", "--name", keeper, *self.options(21001, self.network), self.images["api"], "sleep", "900"])
        namespace = "container:" + keeper
        api = self.start("api", api_volume, namespace)
        witness = self.start("witness", witness_volume, namespace)
        storage = self.start("storage", witness_volume, namespace)
        wake = self.start("wake", api_volume, namespace)
        calls = self.start("calls", api_volume, namespace)
        self.wait_healthy(api, namespace, "http://127.0.0.1:18900/spaces/v1/health")
        self.wait_healthy(witness, namespace, "http://127.0.0.1:17845/livez")
        self.wait_healthy(storage, namespace, "http://127.0.0.1:17846/health", "204")
        self.wait_healthy(wake, namespace, "http://127.0.0.1:8788/wake/health", "204")
        self.wait_healthy(calls, namespace, "http://127.0.0.1:18920/calls/v1/health", "204")
        require(self.status(namespace, "http://127.0.0.1:17845/readyz") == "503", "Witness unexpectedly started unsealed.")
        print("PASS: all services healthy; witness starts sealed", flush=True)

        # This position is chosen from the newly created empty test state, never
        # from observed_position. No client command is sent during this smoke test.
        anchor = {"expected_position": {"sequence": 0, "record_id": None},
                  "public_key": pin["public_key"], "key_generation": pin["key_generation"]}
        wrong = dict(anchor, public_key="00" * 32)
        activation_command = ["exec", "--interactive", witness, "python3", "-B", "/opt/elo/activate.py",
                              "--anchor-stdin", "--first-bootstrap"]
        rejected = run(activation_command, data=json.dumps(wrong), check=False)
        require(rejected.returncode != 0 and "Independent pin does not match this process." in rejected.stderr,
                "Wrong witness anchor was not rejected by the pin validator.")
        require(self.status(namespace, "http://127.0.0.1:17845/readyz") == "503", "Rejected activation changed readiness.")
        run(activation_command, data=json.dumps(anchor))
        require(self.status(namespace, "http://127.0.0.1:17845/readyz") == "200", "Explicit first activation failed.")
        startup_before = json.loads(run(["exec", witness, "cat", "/run/elo-witness/startup.json"]).stdout)
        print("PASS: incorrect anchor rejected; explicit first bootstrap activates this process", flush=True)

        for role, name in (("api", api), ("witness", witness), ("storage", storage)):
            run(["exec", name, "python3", "-c",
                 "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text(sys.argv[2])",
                 f"/var/lib/elo-{role}/.smoke-persistence", self.prefix + "-" + role])

        # Stop/recreate instead of only restarting: mounts must preserve real
        # service databases and keys across the lifetime of a container.
        for name in (api, witness, storage):
            run(["stop", "--time", "30", name])
            run(["rm", name])
        api = self.start("api", api_volume, namespace)
        witness = self.start("witness", witness_volume, namespace)
        storage = self.start("storage", witness_volume, namespace)
        self.wait_healthy(api, namespace, "http://127.0.0.1:18900/spaces/v1/health")
        self.wait_healthy(witness, namespace, "http://127.0.0.1:17845/livez")
        self.wait_healthy(storage, namespace, "http://127.0.0.1:17846/health", "204")
        require(self.status(namespace, "http://127.0.0.1:17845/readyz") == "503", "Recreated witness must be sealed.")
        startup_after = json.loads(run(["exec", witness, "cat", "/run/elo-witness/startup.json"]).stdout)
        require(startup_after["public_key"] == startup_before["public_key"] == pin["public_key"], "Witness signing key changed.")
        require(startup_before["startup_nonce"] != startup_after["startup_nonce"], "Startup nonce was reused.")
        require(startup_after["observed_position"] == startup_before["observed_position"], "Journal position changed without commands.")
        for role, name in (("api", api), ("witness", witness), ("storage", storage)):
            value = run(["exec", name, "cat", f"/var/lib/elo-{role}/.smoke-persistence"]).stdout
            require(value == self.prefix + "-" + role, f"Recreated {role} lost its data-volume marker.")
        print("PASS: all data-volume markers survive recreation; witness retains its key and starts freshly sealed", flush=True)

        input_mount = f"type=volume,src={api_volume},dst=/input,volume-subpath=state/export/config,readonly"
        output_mount = f"type=volume,src={api_volume},dst=/output,volume-subpath=state/export/data"
        self.helper(["elo-team", "hosting-config", "--input", "/input/manifest-input.json", "--key", "/input/signing-key.bin",
                     "--output", "/output/hosting-profile.json", "--qr-output", "/output/hosting-qr.svg"],
                    mounts=(input_mount, output_mount), uid=21005)
        result = self.helper(["python3", "-c", "import json,pathlib; v=json.loads(pathlib.Path('/output/hosting-profile.json').read_text()); assert v['link'].startswith('elo://hosting/v1#'); assert len(v['record'])>100; s=pathlib.Path('/output/hosting-qr.svg').read_text(); assert '<svg' in s and '</svg>' in s; print('valid public profile and QR')"],
                             mounts=(output_mount,), uid=21005)
        require("valid public profile and QR" in result.stdout, "Public export validation failed.")
        print("PASS: offline non-root hosting-config CLI exports the signed profile and local QR SVG", flush=True)
        if self.caddy_image:
            self.check_proxy(api_volume, witness_volume, namespace, tools_mount)
        self.check_media(api_volume, namespace, tools_mount)
        print("NOT TESTED: public DNS/TLS, two-host trust separation, Space enrollment or a real attachment provider", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Tag of the six already-built local images")
    parser.add_argument("--caddy-image", help="Optional already-present Caddy image for isolated HTTP route checks; never pulled")
    parser.add_argument("--media-image", help="Optional already-present LiveKit image; use together with --turn-image")
    parser.add_argument("--turn-image", help="Optional already-present coturn image; use together with --media-image")
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", args.version), "Invalid image version.")
    require(bool(args.media_image) == bool(args.turn_image), "Provide both media and TURN images.")
    smoke = Smoke(args.version, args.caddy_image, args.media_image, args.turn_image)
    try:
        smoke.execute()
    except subprocess.CalledProcessError as error:
        print("Docker command failed: " + (error.stderr or "").strip()[-4096:], file=sys.stderr)
        raise
    finally:
        primary_failure = sys.exc_info()[0] is not None
        cleanup_errors = smoke.cleanup()
        if cleanup_errors:
            print("Cleanup requires attention:\n" + "\n".join(cleanup_errors), file=sys.stderr)
            if not primary_failure:
                raise RuntimeError("Smoke checks passed but cleanup did not complete.")


if __name__ == "__main__":
    main()
