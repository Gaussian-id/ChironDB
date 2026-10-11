"""Exercise the real scikit-learn estimators through the worker contract."""

import unittest

from chirondb_ml_worker import WorkerError, execute


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"region": "north", "price": 1.0, "label": "low", "amount": 2.0},
            {"region": "south", "price": 2.0, "label": "high", "amount": 4.0},
            {"region": "north", "price": 3.0, "label": "low", "amount": 6.0},
            {"region": "south", "price": 4.0, "label": "high", "amount": 8.0},
        ]

    def test_tree_and_forest_classification_and_regression(self):
        for model in ("decision_tree", "random_forest"):
            for task, target in (("classification", "label"), ("regression", "amount")):
                with self.subTest(model=model, task=task):
                    result = execute(
                        {
                            "model": model,
                            "task": task,
                            "features": ["region", "price"],
                            "target": target,
                            "training_rows": self.rows,
                            "prediction_rows": [
                                self.rows[0],
                                {"region": "north", "price": 2.5, target: None},
                                {"region": "south", "price": 3.5, target: None},
                            ],
                        }
                    )
                    self.assertEqual(len(result["predictions"]), 3)
                    self.assertEqual(result["training_rows"], 4)
                    self.assertEqual(result["prediction_rows"], 3)
                    if task == "classification":
                        self.assertTrue(set(result["predictions"]) <= {"low", "high"})
                        self.assertTrue(all(0 <= p <= 1 for p in result["confidence"]))
                    else:
                        self.assertTrue(all(isinstance(p, float) for p in result["predictions"]))
                        self.assertEqual(result["confidence"], [None, None, None])

    def test_rejects_target_leakage(self):
        with self.assertRaisesRegex(WorkerError, "target must be"):
            execute(
                {
                    "model": "decision_tree",
                    "task": "regression",
                    "features": ["amount"],
                    "target": "amount",
                    "training_rows": self.rows,
                    "prediction_rows": [{"amount": None}],
                }
            )

    def test_rejects_removed_models(self):
        for model in ("tabfm", "causilo", "tabpfn", "prior_labs"):
            with self.subTest(model=model), self.assertRaisesRegex(WorkerError, "model or task is unsupported"):
                execute({"model": model, "task": "regression"})

    def test_rejects_feature_with_no_observed_labeled_values(self):
        with self.assertRaisesRegex(WorkerError, "no observed labeled values"):
            execute(
                {
                    "model": "decision_tree",
                    "task": "regression",
                    "features": ["region", "price"],
                    "target": "amount",
                    "training_rows": [
                        {"region": None, "price": 1.0, "amount": 2.0},
                        {"region": None, "price": 2.0, "amount": 4.0},
                    ],
                    "prediction_rows": [{"region": None, "price": 3.0, "amount": None}],
                }
            )


if __name__ == "__main__":
    unittest.main()
