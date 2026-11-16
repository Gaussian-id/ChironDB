"""Run pinned upstream code against files produced by Rust. See README.md."""
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import sys
import urllib.request

HERE = Path(__file__).resolve().parent
WORK = Path(sys.argv[1]).resolve()
WORK.mkdir(exist_ok=True, parents=True)
PINS = {
    "influx": ("influxdata/influxdb", "fde85a2af2a62eec0bb84216786c7a48a61cbd5e"),
    "iotdb": ("apache/iotdb", "7c0de0654c603b5e8356190e2c3df69194993432"),
    "tsfile": ("apache/tsfile", "911a7e684e56fb2822c80009bce823e7ece0bd19"),
}
MANIFEST = json.loads((HERE / "sources.json").read_text())

def digest(path):
    with path.open("rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def verified(path, url, expected):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=120) as src, path.open("wb") as dst:
            shutil.copyfileobj(src, dst)
    if digest(path) != expected:
        raise ValueError(f"source checksum mismatch: {path}")
    return path

def source(repo, filename):
    slug, sha = PINS[repo]
    return verified(WORK / repo / filename, f"https://raw.githubusercontent.com/{slug}/{sha}/{filename}", MANIFEST[f"{repo}/{filename}"])

def run(args, **kwargs):
    subprocess.run(args, check=True, **kwargs)

def go_oracle():
    build = WORK / "go-oracle"
    build.mkdir(exist_ok=True)
    def donor(name):
        return source("influx", "tsdb/engine/tsm1/" + name).read_text()
    for name in ["timestamp.go", "float.go", "bool.go", "bit_reader.go", "writer.go"]:
        (build/name).write_text(donor(name).replace("package tsm1", "package main", 1))
    reader = donor("reader.go")
    enc = donor("encoding.go")
    decls = [re.search(r"^const \(.*?^\)", enc, re.M | re.S).group()]
    for name in ["BlockType", "packBlock", "unpackBlock"]:
        decls.append(re.search(r"^func "+name+r"\(.*?^\}", enc, re.M | re.S).group())
    decls.append(reader[reader.index("type indexEntries struct"):])
    (build/"selected.go").write_text('package main\nimport ("encoding/binary";"fmt";"io")\n'+"\n".join(decls))
    shutil.copy(HERE/"oracle.go",build/"main.go")
    shutil.copy(HERE/"oracle.mod",build/"go.mod")
    shutil.copy(HERE/"oracle.sum",build/"go.sum")
    run(["go","build","-mod=readonly","-o","oracle","."],cwd=build)
    return build/"oracle"

def fixtures():
    # New campaign, independent of the unavailable historical archive.
    out=WORK/"cases"
    out.mkdir(exist_ok=True)
    def put(name, rows):
        path=out/(name+".tsv")
        with path.open("w") as f:
            for tenant,asset,prop,t,tag,bits in rows:
                f.write(f"{tenant}\t{asset}\t{prop}\t{t}\t{tag}\t{bits:016x}\n")
        return path
    edge=[]
    for t,b in [(-(1<<63),1<<63),(-1,0),(0,0x7ff0000000000000),(2**63-1,0xfff0000000000000)]:
        edge.append(("t","edge","raw",t,0,b))
    for i in range(37):
        edge.append(("t","edge","relay",-500+i*10,2,int(i%3==0)))
    yield put("new-edge",edge)
    yield put("new-keylen",[("a","b","c",2,2,1),("a","b","p"*23,2,0,0)])
    # Force block splitting, packed deltas, RLE, raw and singleton lanes.
    main=[("main","motor","speed",i*1000+(i//12)*100,0,struct.unpack(">Q",struct.pack(">d",i/3))[0]) for i in range(2113)]
    yield put("new-main",main)
    for seed in range(1,10):
        rng=random.Random(seed)
        rows=[]
        for i in range(400):
            t=rng.randrange(-100_000,100_000);tag=2 if i%2 else 0
            for _ in range(8):
                t+=rng.randrange(1,1000)
                bits=rng.randrange(2) if tag==2 else struct.unpack(">Q",struct.pack(">d",rng.uniform(-1e6,1e6)))[0]
                rows.append(("tenant","s%03d"%i,"value",t,tag,bits))
        rng.shuffle(rows)
        yield put(f"new-seed-{seed}",rows)

def java_oracle():
    jars=WORK/"jars"
    for coordinate, expected in MANIFEST["jars"].items():
        group,name,version=coordinate.split(":")
        jar=f"{name}-{version}.jar"
        verified(jars/jar,f"https://repo.maven.apache.org/maven2/{group}/{name}/{version}/{jar}",expected)
    classes=WORK/"classes";classes.mkdir(exist_ok=True)
    sources=[source(repo, path.split("/",1)[1]) for path in MANIFEST if path.endswith(".java") for repo in [path.split("/",1)[0]]]
    cp=os.pathsep.join(str(jars/f"{c.split(':')[1]}-{c.split(':')[2]}.jar") for c in MANIFEST["jars"])
    run(["javac","-cp",cp,"-d",classes,*sources,HERE/"TemporalOracle.java"])
    with (WORK/"java.tsv").open("wb") as out:
        run(["java","-cp",str(classes)+os.pathsep+cp,"TemporalOracle"],stdout=out)
    if (WORK/"java.tsv").read_bytes()!=(HERE/"fixtures/java.tsv").read_bytes():
        raise ValueError("Java oracle drift")

def main():
    oracle=go_oracle()
    java_oracle()
    paths=list(fixtures())
    for path in paths:
        path.with_suffix(".rust.tsm").unlink(missing_ok=True)
        run([oracle,"write",path,path.with_suffix(".go.tsm")])
    cases=WORK/"cases"
    run(["cargo","test","--locked","-p","chirondb-temporal","tests::live_upstream_files","--","--ignored","--exact"],cwd=HERE.parents[1],env={**os.environ,"TEMPORAL_CASES":str(cases)})
    for path in paths:
        run([oracle,"check",path,path.with_suffix(".rust.tsm")])
    key=cases/"new-keylen.tsv"
    run([oracle,"keylen",key,key.with_suffix(".rust.tsm")])
    result={p.stem:{"input":digest(p),"tsm":digest(p.with_suffix(".rust.tsm"))} for p in paths}
    (WORK/"parity.json").write_text(json.dumps(result,indent=2)+"\n")
    if result != json.loads((HERE/"fixtures/parity.json").read_text()):
        raise ValueError("pinned input or golden TSM digest drift")
    print(f"PASS: {len(paths)} files, full byte and typed readback parity")

if __name__=="__main__":
    main()
