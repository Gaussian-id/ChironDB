#!/usr/bin/env python3
"""Protected temporal authority through the public TLS query transports."""
import argparse
import json
from pathlib import Path

from security_installation_e2e import InstallationLab, sql_value


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
        # Collection grants cannot authorize a bare, unregistered series name.
        for kind in kinds:
            self.transport(kind, 'writer',
                           "APPEND INTO alpha [{asset:'truck',property:'temp',time_ns:'0',value:0}];",
                           denied=True, not_found=True)
            self.transport(kind, 'reader', latest, denied=True, not_found=True)

        # Explicitly register the historical identity using a trusted template.
        # The registrar has no temporal data grant, and remains denied below.
        self.query('admin', 'CREATE ROLE asset_registrar;')
        self.query('admin', 'GRANT CREATE, INGEST ON COLLECTION alpha TO ROLE asset_registrar;')
        self.query('admin', 'GRANT ROLE asset_registrar TO USER admin;')
        policy = {
            'department_actions': ['temporal_read', 'temporal_append'],
            'owner_actions': [],
            'templates': {'asset': {
                'department': 'Testing', 'classification': 'internal',
                'properties': {
                    '/temp': {'classification': 'internal', 'actions': ['read', 'write']},
                    '/location': {'classification': 'internal', 'actions': ['read', 'query', 'write']},
                    '/private_temp': {'classification': 'restricted', 'actions': ['read', 'write']},
                },
                'representations': {},
            }},
        }
        self.query('admin', 'ALTER COLLECTION alpha SET SECURITY POLICY ' + sql_value(policy) + ';')
        self.query('admin', "REGISTER ASSET alpha ID 'truck' TEMPLATE asset METADATA {location:'north'};")
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
                filtered = self.transport(kind, user, latest[:-1] + " WHERE location = 'north';")
                self.check(f'{kind} {user} metadata filter matches',
                           filtered['rows'][0]['value'] == timestamp, filtered)
                filtered = self.transport(kind, user, latest[:-1] + " WHERE location = 'south';")
                self.check(f'{kind} {user} metadata filter excludes', filtered.get('rows', []) == [], filtered)
                self.transport(kind, user, latest[:-1] + " WHERE private_temp = 0;", denied=True)
                self.transport(kind, user, latest.replace("'temp'", "'private_temp'"), denied=True)
                self.transport(kind, user, latest.replace('alpha', 'beta'), denied=True)
            self.transport(kind, 'writer',
                           "APPEND INTO alpha [{asset:'truck',property:'temp',time_ns:'100',value:100},"
                           "{asset:'truck',property:'private_temp',time_ns:'100',value:100}];",
                           denied=True)
            result = self.transport(kind, 'writer', history)
            self.check(f'{kind} rejected mixed-property append is atomic',
                       len(result['rows']) == timestamp + 1, result)
            self.transport(kind, 'outsider', history, denied=True)
            self.transport(kind, 'admin', latest, denied=True)  # admin has no implicit data grant

        # A SQL -> temporal pipeline requires both domains, including for EXPLAIN.
        self.query('admin', 'SQL CREATE TABLE fleet_assets (id TEXT PRIMARY KEY);')
        self.query('admin', 'GRANT READ, CREATE ON TABLE fleet_assets TO ROLE writer_role;')
        self.query('writer', "SQL INSERT INTO fleet_assets VALUES ('truck');", 1)
        view = self.query('admin', 'SHOW ROW SECURITY fleet_assets LIMIT 16;')['rows'][0]['security']
        row_policy = view['policy']
        revision = row_policy['revision']
        row_policy['revision'] += 1
        template = row_policy['policy']['templates'][row_policy['default_template']]
        template['department'] = 'Testing'
        template['classification'] = 'internal'
        template['properties']['/id']['classification'] = 'internal'
        delta = {'table': view['table'], 'incarnation': view['incarnation'],
                 'expected_revision': revision, 'policy': row_policy, 'records': []}
        self.query('admin', 'ALTER ROW SECURITY fleet_assets APPLY JSON ' +
                   sql_value(json.dumps(delta)) + f' IF REVISION {revision};')
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
