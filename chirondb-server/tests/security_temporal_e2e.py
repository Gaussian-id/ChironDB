#!/usr/bin/env python3
"""Protected temporal authority through the public TLS query transports."""
import argparse
from pathlib import Path

from security_installation_e2e import InstallationLab


class TemporalLab(InstallationLab):
    def verify(self):
        self.run(self.init_args())
        for migration in ['migrate-table-authority', 'migrate-sql-scopes']:
            self.run([self.bin / 'chironctl', 'security', migration,
                      '--data-dir', self.root / 'data', '--keyring', self.keyring])
        self.certificates()
        self.start()
        for collection in ['alpha', 'beta']:
            self.query('admin', f'CREATE PROTECTED COLLECTION {collection} DIM 2;')
        for user, actions in [('writer', 'TEMPORAL_READ, TEMPORAL_APPEND'),
                              ('reader', 'TEMPORAL_READ'), ('outsider', None)]:
            self.query('admin', f'CREATE ROLE {user}_role;')
            if actions:
                self.query('admin', f'GRANT {actions} ON COLLECTION alpha TO ROLE {user}_role;')
            self.query('admin', f'CREATE USER {user} SET DEPARTMENT Testing SET CLEARANCE INTERNAL;')
            self.query('admin', f'GRANT ROLE {user}_role TO USER {user};')
            self.keys[user] = self.secrets / f'{user}.key'
            self.query('admin', f'ISSUE API KEY FOR USER {user};',
                       extra=['--key-out', self.keys[user]])

        latest = "LATEST alpha ASSET 'truck' PROPERTY 'temp';"
        history = "HISTORY alpha ASSET 'truck' PROPERTY 'temp' FROM '-9223372036854775808' TO '9223372036854775807' LIMIT 10;"
        kinds = ['http', 'http-v1', 'grpc', 'wire']
        for timestamp, kind in enumerate(kinds):
            append = f"APPEND INTO alpha [{{asset:'truck',property:'temp',time_ns:'{timestamp}',value:{timestamp}}}];"
            self.transport(kind, 'writer', append)
            self.transport(kind, 'writer', append)  # identical replay remains idempotent
            self.transport(kind, 'reader', append, denied=True)
            self.transport(kind, 'outsider', append, denied=True)
            for user in ['writer', 'reader']:
                result = self.transport(kind, user, latest)
                self.check(f'{kind} {user} latest value', result['rows'][0]['value'] == timestamp)
                result = self.transport(kind, user, history)
                self.check(f'{kind} {user} history excludes duplicate replay',
                           len(result['rows']) == timestamp + 1, result['rows'])
                self.transport(kind, user, latest.replace('alpha', 'beta'), denied=True)
            self.transport(kind, 'outsider', history, denied=True)
            self.transport(kind, 'admin', latest, denied=True)  # admin has no implicit data grant

        # A SQL -> temporal pipeline requires both domains, including for EXPLAIN.
        self.query('admin', 'SQL CREATE TABLE fleet_assets (id TEXT PRIMARY KEY);')
        self.query('admin', 'GRANT READ, CREATE ON TABLE fleet_assets TO ROLE writer_role;')
        self.query('writer', "SQL INSERT INTO fleet_assets VALUES ('truck');")
        pipeline = "PIPELINE\nRELATIONAL r { SQL SELECT id FROM fleet_assets LIMIT 1 }\nTEMPORAL t { LATEST alpha ASSET r.record_ref PROPERTY 'temp' }\nINNER JOIN t ON t.asset_ref = r.record_ref\nRETURN r.id,t.value\nLIMIT 1;"
        for kind in kinds:
            result = self.transport(kind, 'writer', pipeline)
            self.check(f'{kind} pipeline positive', result['rows'] == [{'id': 'truck', 'value': 3.0}], result)
            self.transport(kind, 'reader', pipeline, denied=True)
        self.query('admin', 'REVOKE TEMPORAL_READ ON COLLECTION alpha FROM ROLE writer_role;')
        for kind in kinds:
            self.transport(kind, 'writer', pipeline, denied=True)
            self.transport(kind, 'writer', 'EXPLAIN ' + pipeline, denied=True)
        self.query('admin', 'GRANT TEMPORAL_READ ON COLLECTION alpha TO ROLE writer_role;')

        # Reuse established Wire/gRPC channels after revocation, then restart.
        self.query('admin', 'REVOKE TEMPORAL_READ ON COLLECTION alpha FROM ROLE reader_role;')
        for restart in [False, True]:
            if restart:
                self.stop()
                self.start()
            for kind in kinds:
                self.transport(kind, 'reader', latest, denied=True)
                self.transport(kind, 'reader', history, denied=True)
                self.transport(kind, 'writer', latest)
                self.transport(kind, 'writer', pipeline)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=18501)
    lab = TemporalLab(parser.parse_args())
    passed = False
    try:
        lab.verify()
        passed = True
    finally:
        try:
            lab.stop()
        finally:
            lab.save(passed)
