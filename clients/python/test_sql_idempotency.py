import json
import unittest
from unittest import mock

from chirondb_client import ChironDbClient


class SqlIdempotencyTests(unittest.TestCase):
    def test_both_sql_entrypoints_preserve_the_key_and_separate_correlation(self):
        client = ChironDbClient("http://127.0.0.1:7401")
        response = mock.Mock(ok=True)
        response.json.return_value = {"transaction_id": "stable-decision", "committed": True}
        client._session.post = mock.Mock(return_value=response)
        statement = {"sql": "INSERT INTO documents (id) VALUES ($1)",
                     "parameters": [{"type": "integer", "value": 1}]}
        first = client.execute_sql([statement], retry_id="attempt-1", idempotency_key="operation-1")
        second = client.sql(statement["sql"], statement["parameters"],
                            retry_id="attempt-2", idempotency_key="operation-1")
        self.assertEqual(first, second)
        for attempt, call in enumerate(client._session.post.call_args_list, 1):
            self.assertTrue(call.args[0].endswith('/v1/sql'))
            body = json.loads(call.kwargs['data'])
            self.assertEqual(body['idempotency_key'], 'operation-1')
            self.assertEqual(body['retry_id'], f'attempt-{attempt}')
            self.assertEqual(body['statements'], [statement])

    def test_chironql_preserves_key_without_changing_positional_arguments(self):
        client = ChironDbClient("http://127.0.0.1:7401")
        client._post = mock.Mock(return_value={"committed": True})
        client.chironql("SQL INSERT INTO docs VALUES ($1)",
                       [{"type": "integer", "value": 1}], "attempt", "docs", True, True,
                       idempotency_key="operation")
        path, body = client._post.call_args.args
        self.assertEqual(path, '/v1/chironql')
        self.assertEqual(body['idempotency_key'], 'operation')
        self.assertEqual(body['retry_id'], 'attempt')
        self.assertEqual(body['collection'], 'docs')
        self.assertTrue(body['trace'])
        self.assertTrue(body['confirm'])


if __name__ == '__main__':
    unittest.main()
