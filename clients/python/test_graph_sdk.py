import json
import unittest
from unittest import mock

from chirondb_client import (
    ChironDbClient,
    EdgeToken,
    GraphConstraint,
    GraphDeferredSessionId,
    GraphDeferredSessionResult,
    RelateResult,
    UnrelateResult,
)
from gaussdb_client import EdgeToken as CompatibilityEdgeToken


def response(value: dict) -> mock.Mock:
    result = mock.Mock(ok=True)
    result.json.return_value = value
    return result


RECEIPT = {"graph_epoch": 1, "operation_lsn": 7, "durable": True, "replayed": False}


class GraphSdkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = ChironDbClient("http://127.0.0.1:7401")

    def test_graph_constraint_is_carried_by_search_and_hybrid(self) -> None:
        self.client._session.post = mock.Mock(
            side_effect=[
                response({"hits": [], "degraded": False, "searched": 0, "elapsed_ms": 0}),
                response({"hits": [], "degraded": False, "searched": 0, "elapsed_ms": 0}),
            ]
        )
        graph = GraphConstraint(
            anchors=("root",),
            edge_types=("cites",),
            direction="incoming",
            allow_degraded=True,
        )

        self.client.search("docs", [1.0, 0.0], graph=graph)
        self.client.hybrid_search("docs", vector=[1.0, 0.0], graph=graph)

        for call in self.client._session.post.call_args_list:
            body = json.loads(call.kwargs["data"])
            self.assertEqual(body["graph"]["anchors"], ["root"])
            self.assertEqual(body["graph"]["edge_types"], ["cites"])
            self.assertEqual(body["graph"]["direction"], "incoming")
            self.assertTrue(body["graph"]["allow_degraded"])

    def test_opaque_edge_token_round_trips_without_decoding(self) -> None:
        token_text = "AQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQopaque"
        self.client._session.post = mock.Mock(
            return_value=response({"edge_id": token_text, "receipt": RECEIPT})
        )
        self.client._session.patch = mock.Mock(return_value=response(RECEIPT))
        self.client._session.delete = mock.Mock(
            return_value=response({"deleted": 1, "receipt": RECEIPT})
        )

        related = self.client.relate("docs", "root", "child", "cites")
        self.assertIsInstance(related, RelateResult)
        self.assertIsInstance(related.edge_id, EdgeToken)
        self.assertIs(CompatibilityEdgeToken, EdgeToken)
        self.assertEqual(str(related.edge_id), token_text)

        self.client.merge_edge_properties("docs", related.edge_id, {"weight": 0.8})
        deleted = self.client.unrelate("docs", related.edge_id, wait=False)
        self.assertIsInstance(deleted, UnrelateResult)
        self.assertEqual(deleted.deleted, 1)
        self.assertIn(token_text, self.client._session.patch.call_args.args[0])
        self.assertIn(token_text, self.client._session.delete.call_args.args[0])

    def test_deferred_session_methods_keep_the_session_id_opaque(self) -> None:
        session_text = "opaque-deferred-session"
        self.client._session.post = mock.Mock(
            side_effect=[
                response({"session_id": session_text, "state": "open", "receipt": RECEIPT}),
                response({"edge_id": "opaque-edge", "receipt": RECEIPT}),
                response({"total_points": 2, "bound_endpoints": 2, "receipt": RECEIPT}),
                response(
                    {"session_id": session_text, "state": "committed", "receipt": RECEIPT}
                ),
            ]
        )

        opened = self.client.open_deferred_graph_session("docs", wait=False)
        self.assertIsInstance(opened, GraphDeferredSessionResult)
        self.assertIsInstance(opened.session_id, GraphDeferredSessionId)
        related = self.client.deferred_relate(
            "docs", opened.session_id, "late-a", "late-b", "cites"
        )
        self.client.deferred_upsert(
            "docs",
            opened.session_id,
            [
                {"id": "late-a", "vector": [1.0, 0.0]},
                {"id": "late-b", "vector": [0.0, 1.0]},
            ],
            wait=False,
        )
        committed = self.client.commit_deferred_graph_session("docs", opened.session_id)

        self.assertEqual(related.edge_id.value, "opaque-edge")
        self.assertEqual(committed.state, "committed")
        for call in self.client._session.post.call_args_list[1:]:
            self.assertIn(session_text, call.args[0])


if __name__ == "__main__":
    unittest.main()
