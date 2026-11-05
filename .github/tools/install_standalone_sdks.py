"""Install exact standalone SDK revisions for trusted integration jobs."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
lock = json.loads((root / "sdk-integration/sdk-lock.json").read_text())
cache = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / ("chiron-sdks-" + root.name)
env = dict(os.environ)
if not env.get("SDK_REPOS_READ_TOKEN"):
    raise SystemExit("configure read-only SDK_REPOS_READ_TOKEN for private SDK integration")
cache.mkdir(parents=True, exist_ok=True)
helper = cache / "git-credential-sdk"
helper.write_text('#!/bin/sh\nif [ "$1" = get ]; then printf "username=x-access-token\\npassword=%s\\n" "$SDK_REPOS_READ_TOKEN"; fi\n')
helper.chmod(0o700)
env.update(GIT_CONFIG_COUNT="2", GIT_CONFIG_KEY_0="credential.helper", GIT_CONFIG_VALUE_0="", GIT_CONFIG_KEY_1="credential.helper", GIT_CONFIG_VALUE_1=str(helper), CARGO_NET_GIT_FETCH_WITH_CLI="true")
paths = {}
try:
    for language, entry in lock.items():
        revision = entry["revision"]
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise SystemExit("SDK revision must be a full commit hash")
        checkout = cache / language
        if not checkout.exists():
            subprocess.run(["git", "clone", "--no-checkout", "https://github.com/" + entry["repository"] + ".git", str(checkout)], env=env, check=True)
        subprocess.run(["git", "fetch", "origin", revision], cwd=checkout, env=env, check=True)
        subprocess.run(["git", "checkout", "--detach", revision], cwd=checkout, env=env, check=True)
        paths[language] = checkout
    for manifest in (root / "sdk-integration/Cargo.toml", paths["rust"] / "Cargo.toml"):
        subprocess.run(["cargo", "fetch", "--locked", "--manifest-path", str(manifest)], env=env, check=True)
finally:
    helper.unlink(missing_ok=True)
# Child fixtures and build tools do not need the repository read credential.
env.pop("SDK_REPOS_READ_TOKEN", None)
for key in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_KEY_1", "GIT_CONFIG_VALUE_1"): env.pop(key, None)
py = paths["python"]
subprocess.run([sys.executable, "-m", "pip", "install", "build"], env=env, check=True)
subprocess.run([sys.executable, "-m", "build", "--wheel"], cwd=py, env=env, check=True)
wheel = next((py / "dist").glob("*.whl"))
subprocess.run([sys.executable, "-m", "pip", "install", str(wheel) + "[async,dev]"], env=env, check=True)
if "GITHUB_ENV" in os.environ:
    with open(os.environ["GITHUB_ENV"], "a") as out:
        out.write(f"CHIRONDB_SDK_PYTHON_ROOT={py}\n")
        out.write(f"CHIRONDB_SDK_RUST_ROOT={paths['rust']}\n")
        out.write(f"CHIRONDB_SDK_NODE_ROOT={paths['node']}\n")
print(json.dumps({language: str(path) for language, path in paths.items()}))
