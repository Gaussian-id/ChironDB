#!/usr/bin/env python3
import json
import socket
import struct
import sys


WIRE_VARINT = 0
WIRE_LEN = 2
REQUEST_ID = 501


def encode_varint(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_key(field_number, wire_type):
    return encode_varint((field_number << 3) | wire_type)


def encode_varint_field(field_number, value):
    return encode_key(field_number, WIRE_VARINT) + encode_varint(value)


def encode_len_field(field_number, payload):
    return encode_key(field_number, WIRE_LEN) + encode_varint(len(payload)) + payload


def decode_varint(data, offset):
    shift = 0
    value = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def parse_fields(data):
    fields = {}
    offset = 0
    while offset < len(data):
        key, offset = decode_varint(data, offset)
        field_number = key >> 3
        wire_type = key & 0x07
        if wire_type == WIRE_VARINT:
            value, offset = decode_varint(data, offset)
        elif wire_type == WIRE_LEN:
            length, offset = decode_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise ValueError("truncated length-delimited field")
            value = data[offset:end]
            offset = end
        else:
            raise ValueError(f"unsupported wire type {wire_type}")
        fields.setdefault(field_number, []).append((wire_type, value))
    return fields


def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: gausswire_python_compat.py HOST:PORT")
    host, raw_port = sys.argv[1].rsplit(":", 1)
    request = (
        encode_varint_field(1, REQUEST_ID)
        + encode_len_field(10, b"")
    )
    frame = struct.pack(">I", len(request)) + request

    with socket.create_connection((host, int(raw_port)), timeout=5.0) as sock:
        sock.sendall(frame)
        response_len = struct.unpack(">I", recv_exact(sock, 4))[0]
        response = recv_exact(sock, response_len)

    fields = parse_fields(response)
    request_id = fields[1][0][1]
    if request_id != REQUEST_ID:
        raise AssertionError(f"request_id mismatch: {request_id}")
    if 2 in fields and fields[2][0][1]:
        raise AssertionError(f"unexpected error_code: {fields[2][0][1]!r}")
    if 10 not in fields:
        raise AssertionError("missing health payload")

    health = parse_fields(fields[10][0][1])
    status = health[1][0][1].decode("utf-8")
    if status != "ok":
        raise AssertionError(f"unexpected health status: {status}")

    print(json.dumps({"request_id": request_id, "status": status}))


if __name__ == "__main__":
    main()
