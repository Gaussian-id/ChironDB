"""Run both Random Forest ChironQL tasks against an unprotected localhost preview.

Creates uniquely named synthetic source/result tables; does not change existing data.
Install the worker dependencies and start ChironDB as described in README.md first.
"""

import json
import time
import urllib.request
import uuid


BASE = "http://127.0.0.1:7401"


def request(path, query=None):
    body = None if query is None else json.dumps({"query": query}).encode()
    response = urllib.request.urlopen(urllib.request.Request(
        BASE + path, data=body, headers={"Content-Type": "application/json"},
    ), timeout=30)
    with response:
        return json.load(response)


def main():
    source = "ml_trial_" + uuid.uuid4().hex[:12]
    request("/v1/chironql", f"SQL CREATE TABLE {source} (id INTEGER PRIMARY KEY, price DOUBLE PRECISION, label TEXT, amount DOUBLE PRECISION)")
    request("/v1/chironql", f"SQL INSERT INTO {source} VALUES (1,1,'low',2), (2,2,'high',4), (3,3,'low',6), (4,4,'high',8), (5,5,'low',10), (6,6,'high',12), (7,2.5,NULL,NULL), (8,3.5,NULL,NULL)")
    for task, target in [("CLASSIFICATION", "label"), ("REGRESSION", "amount")]:
        view = source + "_" + task.lower()
        query = f"ML MATERIALIZE {view} FROM {source} TARGET {target} FEATURES (price) TASK {task} USING RANDOM_FOREST;"
        print(query, flush=True)
        submitted = request("/v1/chironql", query)
        job_id = submitted["rows"][0]["job_id"]
        deadline = time.monotonic() + 310
        while time.monotonic() < deadline:
            job = request("/v1/ml/jobs/" + job_id)
            if job["status"] == "failed":
                raise RuntimeError(job["error"])
            if job["status"] == "succeeded":
                print(json.dumps(job, indent=2), flush=True)
                print(json.dumps(request("/v1/chironql", f"SQL SELECT * FROM {view} ORDER BY id"), indent=2), flush=True)
                break
            time.sleep(0.2)
        else:
            raise TimeoutError(f"ML job {job_id} did not complete")
    print(f"Source and prediction tables retained under {source}; synthetic smoke only, no quality claim.")


if __name__ == "__main__":
    main()
