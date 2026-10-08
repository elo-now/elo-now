#!/usr/bin/env python3
"""Prepare a profile-bound Tauri overlay for local macOS development testing.

This does not sign, install, publish, or export a private key. Apple and macOS
remain responsible for validating the profile and the final code signature.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
TEAM = "F3HJA47BQU"
BUNDLE = "now.elo"
APP_ID = f"{TEAM}.{BUNDLE}"
DOMAIN = "webcredentials:elo.now"


def checked_output(command: list[str], *, data: bytes | None = None) -> bytes:
    result = subprocess.run(command, input=data, capture_output=True, check=False)
    if result.returncode:
        # Tool diagnostics may contain profile data or hardware identifiers.
        raise ValueError(f"{Path(command[0]).name} failed; check local signing access")
    return result.stdout


def allows(grants: object, requested: str) -> bool:
    if not isinstance(grants, list):
        return False
    return any(
        isinstance(grant, str)
        and (grant == requested or (grant.endswith("*") and requested.startswith(grant[:-1])))
        for grant in grants
    )


def validate_profile(
    profile: dict,
    identity: str,
    device: str,
    now: datetime,
    webcredentials: bool,
) -> dict:
    """Check only the requested local development scope; never emit profile data."""
    if "OSX" not in profile.get("Platform", []):
        raise ValueError("A macOS development profile is required; an iOS profile cannot be used")
    entitlements = profile.get("Entitlements", {})
    if (
        profile.get("TeamIdentifier") != [TEAM]
        or entitlements.get("com.apple.developer.team-identifier") != TEAM
        or entitlements.get("com.apple.application-identifier") != APP_ID
    ):
        raise ValueError("The profile must authorize the exact elo.now macOS app and team")
    expiry = profile.get("ExpirationDate")
    if isinstance(expiry, datetime) and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if not isinstance(expiry, datetime) or expiry <= now:
        raise ValueError("The provisioning profile is expired or has no expiration date")
    # Current macOS development profiles may omit the debugging entitlement.
    # The installed Apple Development identity and exact provisioned Mac are
    # validated independently; this app never requests debugging permission.
    debugging = entitlements.get("get-task-allow", entitlements.get("com.apple.security.get-task-allow"))
    if debugging is False:
        raise ValueError("A development profile is required for this local test overlay")
    if not device or device not in profile.get("ProvisionedDevices", []):
        raise ValueError("The development profile does not include this Mac")
    certificates = profile.get("DeveloperCertificates", [])
    if not any(isinstance(cert, bytes) and hashlib.sha1(cert).hexdigest().upper() == identity for cert in certificates):
        raise ValueError("The selected signing certificate is not authorized by the profile")
    if not allows(entitlements.get("keychain-access-groups"), APP_ID):
        raise ValueError("The profile does not authorize the private elo.now Keychain access group")
    if webcredentials and not allows(entitlements.get("com.apple.developer.associated-domains"), DOMAIN):
        raise ValueError("The profile does not authorize Associated Domains; regenerate it after enabling the capability")
    with (ROOT / "apps/desktop/src-tauri/macos/Entitlements.plist").open("rb") as stream:
        result = plistlib.load(stream)
    result.update({
        "com.apple.application-identifier": APP_ID,
        "com.apple.developer.team-identifier": TEAM,
        "keychain-access-groups": [APP_ID],
    })
    if webcredentials:
        result["com.apple.developer.associated-domains"] = [DOMAIN]
    # A development profile may allow debugging; the test app does not need it.
    return result


def write_private(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(data)


def write_overlay(output: Path, profile_bytes: bytes, identity: str, entitlements: dict) -> Path:
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    entitlement_path = output / "Entitlements.plist"
    profile_path = output / "embedded.provisionprofile"
    write_private(entitlement_path, plistlib.dumps(entitlements))
    write_private(profile_path, profile_bytes)
    config = {
        "identifier": BUNDLE,
        "bundle": {"macOS": {
            "signingIdentity": identity,
            "hardenedRuntime": True,
            "entitlements": str(entitlement_path),
            "files": {"embedded.provisionprofile": str(profile_path)},
        }},
    }
    destination = output / "tauri.macos-development.conf.json"
    write_private(destination, (json.dumps(config, indent=2) + "\n").encode())
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--identity", required=True, help="SHA-1 of an installed Apple Development signing identity")
    parser.add_argument("--output", required=True, type=Path, help="New private directory; existing output is never overwritten")
    parser.add_argument("--webcredentials", action="store_true", help="Also require and include webcredentials:elo.now")
    args = parser.parse_args()
    identity = args.identity.upper()
    if not re.fullmatch(r"[0-9A-F]{40}", identity):
        parser.error("--identity must be a certificate SHA-1, not a name or an ad hoc identity")
    try:
        if args.profile.is_symlink() or not args.profile.is_file():
            raise ValueError("Provide a regular provisioning profile file")
        profile_bytes = args.profile.read_bytes()
        profile = plistlib.loads(checked_output(["/usr/bin/security", "cms", "-D"], data=profile_bytes))
        if not isinstance(profile, dict):
            raise ValueError("The provisioning profile must contain a property-list dictionary")
        if "OSX" not in profile.get("Platform", []):
            raise ValueError("A macOS development profile is required; an iOS profile cannot be used")
        identities = checked_output(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"]).decode()
        if not re.search(r'\b' + identity + r'\s+"Apple Development:', identities):
            raise ValueError("The selected Apple Development certificate and private key are not available")
        hardware = json.loads(checked_output(["/usr/sbin/system_profiler", "SPHardwareDataType", "-json"]))
        device = hardware["SPHardwareDataType"][0].get("provisioning_UDID", "")
        entitlements = validate_profile(profile, identity, device, datetime.now(timezone.utc), args.webcredentials)
        destination = write_overlay(args.output, profile_bytes, identity, entitlements)
        print(f"Prepared local macOS development overlay: {destination}")
        print("No app was built, signed, installed, or published.")
    except (ValueError, OSError, KeyError, IndexError, plistlib.InvalidFileException) as error:
        parser.exit(2, f"Cannot prepare macOS signing: {error}\n")


if __name__ == "__main__":
    main()
