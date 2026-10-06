"""Shared allowlisted admin input validation; errors never include input values."""
import re
import unicodedata
from urllib.parse import urlsplit

MAX_BODY = 32 * 1024
HEX_ID = re.compile(r"[0-9a-f]{64}\Z")
FOLDER = re.compile(r"https://mega\.nz/folder/[A-Za-z0-9_-]{8}#[A-Za-z0-9_-]{22,64}\Z")
AUTH = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
RETENTIONS = (21600, 43200, 86400, 172800, "no_expiry")
API_FIELDS = {"name", "message_lifetimes", "default_message_lifetime", "creation_mode", "allowed_creators", "managed_provider"}
WITNESS_FIELDS = {"provider", "allowed_owners", "folder_link", "write_auth", "s3_endpoint", "s3_region", "s3_bucket", "s3_access_key", "s3_secret_key"}
S3_PUBLIC = ("s3_endpoint", "s3_region", "s3_bucket")
S3_SECRET = ("s3_access_key", "s3_secret_key")


class ValidationError(ValueError):
    pass


def require(condition, message="Invalid configuration."):
    if not condition:
        raise ValidationError(message)


def text(value, maximum, *, minimum=1):
    require(isinstance(value, str))
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValidationError("Invalid configuration.") from None
    require(minimum <= size <= maximum and not any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value))
    return value


def owners(value):
    require(isinstance(value, list) and len(value) <= 1024, "Invalid identity list.")
    require(all(isinstance(item, str) and HEX_ID.fullmatch(item) for item in value), "Invalid identity list.")
    require(len(set(value)) == len(value), "Duplicate identity.")
    return sorted(value)


def origin(value):
    text(value, 2048)
    try:
        parsed = urlsplit(value)
        port = parsed.port
        require(value.isascii() and value.startswith("https://") and parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
                and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment
                and not any(c.isspace() for c in value) and not any(c in value for c in "\\?#"),
                "An HTTPS origin is required.")
        require(port is None or 1 <= port <= 65535, "An HTTPS origin is required.")
        # URI whitespace, encoded host names and user-info ambiguities are not accepted.
        require("%" not in parsed.netloc and "@" not in parsed.netloc, "An HTTPS origin is required.")
    except (ValueError, UnicodeError):
        raise ValidationError("An HTTPS origin is required.") from None
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return "https://" + host + (f":{port}" if port is not None and port != 443 else "")


def s3_public(value):
    endpoint = origin(value["s3_endpoint"])
    region = text(value["s3_region"], 128)
    bucket = text(value["s3_bucket"], 255)
    require(re.fullmatch(r"[A-Za-z0-9-]{1,128}", region) is not None, "Invalid storage region.")
    require(re.fullmatch(r"[A-Za-z0-9.-]{1,255}", bucket) is not None, "Invalid storage bucket.")
    return {"s3_endpoint": endpoint, "s3_region": region, "s3_bucket": bucket}


def validate_configuration(role, value):
    require(isinstance(value, dict))
    if role == "api":
        require(set(value) == API_FIELDS)
        name = text(value["name"], 96)
        require(name == name.strip(), "Invalid hosting name.")
        lifetimes = value["message_lifetimes"]
        require(isinstance(lifetimes, list) and 1 <= len(lifetimes) <= 5, "Invalid message lifetime choices.")
        require(all(type(item) in (int, str) and item in RETENTIONS for item in lifetimes)
                and len(set(lifetimes)) == len(lifetimes), "Invalid message lifetime choices.")
        default = value["default_message_lifetime"]
        require(type(default) in (int, str) and default in lifetimes, "Invalid default message lifetime.")
        mode = value["creation_mode"]
        require(mode in ("public", "allowlist"), "Invalid creation mode.")
        allowed = owners(value["allowed_creators"])
        managed = value["managed_provider"]
        require(managed in (None, "mega", "s3"), "Invalid managed storage provider.")
        require(mode != "public" or (not allowed and managed is None), "Public hosting cannot provide managed storage or a creator allowlist.")
        return {"name": name, "message_lifetimes": [item for item in RETENTIONS if item in lifetimes],
                "default_message_lifetime": default, "creation_mode": mode, "allowed_creators": allowed, "managed_provider": managed}
    require(role == "witness")
    require(not set(value) - WITNESS_FIELDS and {"provider", "allowed_owners"} <= set(value))
    provider = value["provider"]
    require(provider in (None, "mega", "s3"), "Invalid managed storage provider.")
    result = {"provider": provider, "allowed_owners": owners(value["allowed_owners"])}
    supplied = {key: text(value.get(key, ""), 4096, minimum=0) for key in WITNESS_FIELDS - {"provider", "allowed_owners"}}
    if provider is None:
        require(not any(supplied.values()), "Disabled storage cannot include credentials.")
    elif provider == "mega":
        require(not any(supplied[key] for key in (*S3_PUBLIC, *S3_SECRET)), "Unexpected provider fields.")
        folder, auth = supplied["folder_link"], supplied["write_auth"]
        require(bool(folder) == bool(auth), "Enter both MEGA folder credentials.")
        if folder:
            require(FOLDER.fullmatch(folder) and AUTH.fullmatch(auth), "Invalid limited MEGA folder credentials.")
            result.update(folder_link=folder, write_auth=auth)
    else:
        require(not supplied["folder_link"] and not supplied["write_auth"], "Unexpected provider fields.")
        result.update(s3_public(supplied))
        access, secret = supplied["s3_access_key"], supplied["s3_secret_key"]
        require(bool(access) == bool(secret), "Enter both storage credentials.")
        if access:
            require(re.fullmatch(r"[A-Za-z0-9/+=._:@-]{1,256}", access), "Invalid storage access key.")
            result.update(s3_access_key=access, s3_secret_key=text(secret, 4096))
    return result


def public_configuration(role, value):
    """Only the published state projection may leave the local admin service."""
    require(isinstance(value, dict))
    if role == "api":
        result = validate_configuration(role, {key: value[key] for key in API_FIELDS if key in value})
        result["storage_available"] = value.get("storage_available") is True
        return result
    require(role == "witness")
    provider = value.get("provider")
    require(provider in (None, "mega", "s3"))
    result = {"provider": provider, "configured": value.get("configured") is True,
              "allowed_owners": owners(value.get("allowed_owners", []))}
    if provider == "s3" and isinstance(value.get("public_fields"), dict):
        result["public_fields"] = s3_public(value["public_fields"])
    return result
