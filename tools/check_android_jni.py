#!/usr/bin/env python3
"""Check native WebRTC entry points in a final, minified APK or AAB.

Inspect DEX class definitions and declared methods, not string references: a
class name can remain in a DEX string table after R8 removes the actual class.
This check does not load native code or replace a call test on an Android device.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import struct
import sys
import zipfile


REQUIRED_METHODS = {
    "org.jni_zero.JniZero": {
        "init()[Ljava/lang/Object;",
        "crashIfMultiplexingMisaligned(JJ)V",
    },
    "org.jni_zero.CommonApis": {
        "mapToArray(Ljava/util/Map;)[Ljava/lang/Object;",
        "arrayToMap([Ljava/lang/Object;)Ljava/util/Map;",
    },
    "livekit.org.jni_zero.JniInit": {
        "init()[Ljava/lang/Object;",
        "crashIfMultiplexingMisaligned(JJ)V",
    },
    "livekit.org.jni_zero.JniUtil": {
        "mapToArray(Ljava/util/Map;)[Ljava/lang/Object;",
        "arrayToMap([Ljava/lang/Object;)Ljava/util/Map;",
    },
}
DEX_ENTRY = re.compile(r"(?:base/dex/)?classes(?:[2-9]|[1-9][0-9]+)?\.dex\Z")


def dex_definitions(data: bytes) -> dict[str, dict[str, int]]:
    """Return class -> declared method signature -> access flags."""
    if len(data) < 112 or not re.fullmatch(rb"dex\n0(?:35|37|38|39|40)\0", data[:8]):
        raise ValueError("Unsupported or invalid DEX header")

    def read(offset: int, fmt: str):
        size = struct.calcsize("<" + fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError("DEX table extends beyond the file")
        return struct.unpack_from("<" + fmt, data, offset)

    file_size, header_size, endian = read(32, "III")
    if file_size != len(data) or header_size != 112 or endian != 0x12345678:
        raise ValueError("Invalid DEX size or byte order")

    def uleb(offset: int) -> tuple[int, int]:
        value = 0
        for shift in range(0, 35, 7):
            byte, = read(offset, "B")
            offset += 1
            value |= (byte & 0x7F) << shift
            if byte < 128:
                return value, offset
        raise ValueError("Invalid DEX variable-length integer")

    def table(header_offset: int, fmt: str):
        count, start = read(header_offset, "II")
        size = struct.calcsize("<" + fmt)
        if count > len(data) // size or start + count * size > len(data):
            raise ValueError("Invalid DEX table size")
        return [read(start + index * size, fmt) for index in range(count)]

    strings = []
    for offset, in table(56, "I"):
        _, start = uleb(offset)
        end = data.find(b"\0", start)
        if end < 0:
            raise ValueError("Unterminated DEX string")
        # Required JNI descriptors are ASCII; unrelated MUTF-8 text is ignored.
        strings.append(data[start:end].decode("utf-8", errors="replace"))
    types = [strings[index] for index, in table(64, "I")]
    prototypes = []
    for _, result, parameters in table(72, "III"):
        arguments = []
        if parameters:
            count, = read(parameters, "I")
            if count > len(data) // 2:
                raise ValueError("Invalid DEX parameter count")
            arguments = [types[read(parameters + 4 + index * 2, "H")[0]] for index in range(count)]
        prototypes.append("(" + "".join(arguments) + ")" + types[result])
    methods = [(types[owner], strings[name] + prototypes[prototype])
               for owner, prototype, name in table(88, "HHI")]
    definitions = {}
    for owner, _, _, _, _, _, class_data, _ in table(96, "IIIIIIII"):
        descriptor = types[owner]
        name = descriptor.removeprefix("L").removesuffix(";").replace("/", ".")
        declared = {}
        if class_data:
            counts = []
            cursor = class_data
            for _ in range(4):
                count, cursor = uleb(cursor)
                counts.append(count)
            if sum(counts) > len(data):
                raise ValueError("Invalid DEX member count")
            for _ in range(counts[0] + counts[1]):
                _, cursor = uleb(cursor)
                _, cursor = uleb(cursor)
            for count in counts[2:]:
                method_index = 0
                for _ in range(count):
                    delta, cursor = uleb(cursor)
                    flags, cursor = uleb(cursor)
                    _, cursor = uleb(cursor)
                    method_index += delta
                    method_owner, signature = methods[method_index]
                    if method_owner != descriptor:
                        raise ValueError("Invalid DEX method owner")
                    declared[signature] = flags
        if name in definitions:
            raise ValueError("Duplicate DEX class definition")
        definitions[name] = declared
    return definitions


def check_artifact(path: Path) -> list[str]:
    definitions = {}
    with zipfile.ZipFile(path) as archive:
        entries = [info for info in archive.infolist() if DEX_ENTRY.fullmatch(info.filename)]
        if not entries or len(entries) > 64:
            raise ValueError("Expected Android base-module DEX files")
        for info in entries:
            if info.file_size > 128 * 1024 * 1024:
                raise ValueError("DEX file exceeds the inspection limit")
            current = dex_definitions(archive.read(info))
            if definitions.keys() & current.keys():
                raise ValueError("Duplicate class definitions across DEX files")
            definitions.update(current)
    errors = []
    for name, expected in REQUIRED_METHODS.items():
        if name not in definitions:
            errors.append("Missing JNI runtime class: " + name)
            continue
        for signature in sorted(expected):
            flags = definitions[name].get(signature)
            if flags is None or not flags & 0x8:
                errors.append("Missing static JNI entry point: " + name + "." + signature)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    try:
        errors = check_artifact(args.artifact)
    except (OSError, ValueError, IndexError, struct.error, zipfile.BadZipFile) as error:
        print("Android JNI check failed: " + str(error), file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Android JNI entry points: PASS (direct WebRTC and LiveKit runtime)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
