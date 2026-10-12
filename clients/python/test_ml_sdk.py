"""Verify the ML SDK constructs the public ChironQL and HTTP requests."""

import unittest
from unittest.mock import patch

from chirondb_client import ChironDbClient


class MlSdkTests(unittest.TestCase):
    def setUp(self):
        self.client = ChironDbClient("http://127.0.0.1:7401")

    def test_same_query_for_refresh(self):
        with patch.object(self.client, "chironql", return_value={"rows": []}) as execute:
            arguments = ("forecast", "sales", "demand", ["region", "price"], "regression", "random_forest")
            self.client.materialize_ml(*arguments)
            self.client.materialize_ml(*arguments)
        self.assertEqual(execute.call_count, 2)
        query = "ML MATERIALIZE forecast FROM sales TARGET demand FEATURES (region, price) TASK REGRESSION USING RANDOM_FOREST;"
        self.assertEqual(execute.call_args_list[0].args, (query,))
        self.assertEqual(execute.call_args_list[1].args, (query,))

    def test_model_and_task_matrix_uses_same_parameter_order(self):
        with patch.object(self.client, "chironql", return_value={}) as execute:
            for task in ("classification", "regression"):
                for model in ("decision_tree", "random_forest"):
                    self.client.materialize_ml("forecast", "sales", "demand", ["price"], task, model)
                    query = execute.call_args.args[0]
                    self.assertEqual(
                        query,
                        f"ML MATERIALIZE forecast FROM sales TARGET demand FEATURES (price) TASK {task.upper()} USING {model.upper()};",
                    )

    def test_get_job_and_view_paths(self):
        with patch.object(self.client, "_get", return_value={}) as get:
            self.client.get_ml_job("job-123")
            self.client.get_ml_view("forecast", limit=2, cursor="id=1&v=2")
        self.assertEqual(get.call_args_list[0].args, ("/v1/ml/jobs/job-123",))
        self.assertEqual(get.call_args_list[1].args, ("/v1/ml/views/forecast?limit=2&cursor=id%3D1%26v%3D2",))

    def test_rejects_unsafe_identifiers(self):
        with self.assertRaises(ValueError):
            self.client.materialize_ml("forecast; DROP TABLE sales", "sales", "demand", ["price"], "regression", "decision_tree")

    def test_rejects_removed_models_before_sending_request(self):
        with patch.object(self.client, "chironql") as execute:
            for model in ("tabfm", "causilo", "tabpfn", "prior_labs"):
                with self.subTest(model=model), self.assertRaisesRegex(ValueError, "model is unsupported"):
                    self.client.materialize_ml("forecast", "sales", "demand", ["price"], "regression", model)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
