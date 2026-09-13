import base64
import json
import unittest
from unittest import mock

from chirondb_client import (
    ChironDbClient,
    StructuralPoint,
    UnsafeStructuralEmbeddingOverride,
)


class StructuralPointTests(unittest.TestCase):
    def test_zero_vector_is_rejected_by_default(self) -> None:
        with self.assertRaisesRegex(ValueError, "all-zero vector"):
            StructuralPoint.create({"id": "line-3", "vector": [0.0, -0.0]})

    def test_override_requires_a_reason(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            UnsafeStructuralEmbeddingOverride("  ")

    def test_unsafe_reason_is_sent_for_server_audit(self) -> None:
        client = ChironDbClient("http://127.0.0.1:7401")
        response = mock.Mock(ok=True)
        response.json.return_value = {
            "total": 1,
            "operation_lsn": 42,
            "unsafe_override_audited": True,
        }
        client._session.put = mock.Mock(return_value=response)
        reason = "legacy import cannot be re-embedded"
        point = StructuralPoint.with_unsafe_zero_vector_override(
            {"id": "line-3", "vector": [0.0, 0.0]},
            UnsafeStructuralEmbeddingOverride(reason),
        )

        result = client.upsert_structural("assets", [point])

        self.assertTrue(result["unsafe_override_audited"])
        _, kwargs = client._session.put.call_args
        self.assertEqual(kwargs["headers"]["x-chiron-structural-points"], "1")
        encoded = kwargs["headers"]["x-chiron-unsafe-structural-embedding-reason"]
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
        self.assertEqual(decoded, reason)
        self.assertEqual(json.loads(kwargs["data"])["points"][0]["id"], "line-3")


if __name__ == "__main__":
    unittest.main()
