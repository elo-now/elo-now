#!/usr/bin/env python3
"""Allocate one disposable relay using coturn's REST credentials; no peer traffic."""

import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import time

MAGIC = 0x2112A442


def attribute(kind, data):
    return struct.pack('!HH', kind, len(data)) + data + bytes((-len(data)) % 4)


def request(attributes, key=None):
    transaction = os.urandom(12)
    header = struct.pack('!HHI12s', 0x0003, len(attributes) + (24 if key else 0), MAGIC, transaction)
    packet = header + attributes
    if key:
        packet += attribute(0x0008, hmac.new(key, packet, hashlib.sha1).digest())
    return transaction, packet


def response(data, transaction):
    kind, length, magic, received = struct.unpack('!HHI12s', data[:20])
    if magic != MAGIC or received != transaction or len(data) != length + 20:
        raise RuntimeError('Invalid TURN response.')
    values = {}
    offset = 20
    while offset < len(data):
        field, size = struct.unpack('!HH', data[offset:offset + 4])
        values[field] = data[offset + 4:offset + 4 + size]
        offset += 4 + size + (-size) % 4
    return kind, values


def allocate(host, secret):
    username = str(int(time.time()) + 60) + ':container-smoke'
    credential = base64.b64encode(hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()).decode()
    transport = attribute(0x0019, b'\x11\x00\x00\x00')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(5)
        transaction, packet = request(transport)
        connection.sendto(packet, (host, 3478))
        kind, values = response(connection.recv(4096), transaction)
        if kind != 0x0113 or values.get(0x0009, b'')[:4] != b'\x00\x00\x04\x01':
            raise RuntimeError('TURN did not require authentication.')
        realm, nonce = values[0x0014], values[0x0015]
        # TURN's long-term authentication specifies this MD5 key derivation;
        # the password here is a generated short-lived HMAC credential.
        key = hashlib.md5(username.encode() + b':' + realm + b':' + credential.encode()).digest()
        transaction, packet = request(transport + attribute(0x0006, username.encode())
                                      + attribute(0x0014, realm) + attribute(0x0015, nonce), key)
        connection.sendto(packet, (host, 3478))
        kind, values = response(connection.recv(4096), transaction)
        if kind != 0x0103 or 0x0016 not in values:
            raise RuntimeError('Authenticated TURN allocation failed.')
    print('PASS: TURN rejects unauthenticated allocation and accepts short-lived HMAC credentials')


if __name__ == '__main__':
    value = json.load(sys.stdin)
    allocate(value['host'], value['secret'])
