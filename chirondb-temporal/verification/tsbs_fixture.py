"""Project TSBS IoT readings into typed scalar samples, without a server."""
import hashlib
from pathlib import Path
import struct
import sys

source, target = map(Path, sys.argv[1:])
expected = "2a304fc29f8f4c90fe885ba9bcc2e620d220d2719e79c68eef0f1fdee7154baf"
if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
    raise ValueError("unexpected TSBS fixture; use the pinned generator and flags")
rows = []
for line in source.read_text().splitlines():
    labels, fields, time = line.split(" ")
    if labels.split(",")[0] != "readings":
        continue
    tags = dict(tag.split("=", 1) for tag in labels.split(",")[1:])
    for pair in fields.split(","):
        name, value = pair.split("=")
        if name in {"latitude","velocity"}:
            bits = struct.pack(">d",float(value)).hex()
            rows.append(f"tsbs\t{tags['name']}\t{name}\t{time}\t0\t{bits}\n")
target.write_text("".join(rows))
