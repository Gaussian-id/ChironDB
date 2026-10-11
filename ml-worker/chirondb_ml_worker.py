"""Optional, single-request tabular ML worker for ChironDB.

The server starts this process with a pinned Python environment and sends one
JSON request on stdin. Only one JSON response is written to stdout; diagnostics
belong on stderr. The request contains no storage path or server credentials;
the worker is a trusted local process with the server user's OS permissions.
"""

from __future__ import annotations

import json
import sys
from typing import Any


MODELS = {"decision_tree", "random_forest"}
TASKS = {"classification", "regression"}


class WorkerError(ValueError):
    pass


def _frame(request: dict[str, Any]):
    import pandas as pd

    features = request.get("features")
    target = request.get("target")
    training = request.get("training_rows")
    prediction = request.get("prediction_rows")
    if not isinstance(features, list) or not features or not all(
        isinstance(name, str) and name for name in features
    ) or len(set(features)) != len(features):
        raise WorkerError("features must be a nonempty list of distinct names")
    if not isinstance(target, str) or not target or target in features:
        raise WorkerError("target must be a name outside features")
    if not isinstance(training, list) or not training or not isinstance(prediction, list):
        raise WorkerError("training_rows must be nonempty and prediction_rows must be a list")
    if not prediction:
        raise WorkerError("prediction_rows must contain at least one row")
    for row in training + prediction:
        if not isinstance(row, dict) or any(feature not in row for feature in features):
            raise WorkerError("every row must contain every feature")
    if any(target not in row or row[target] is None for row in training):
        raise WorkerError("training targets must be present and non-null")
    # The published view also includes fitted rows and their actual values.
    # Only the explicit feature frame reaches predict(), so those target
    # values cannot leak into model inputs.
    x_train = pd.DataFrame(training, columns=features)
    x_predict = pd.DataFrame(prediction, columns=features)
    y_train = pd.Series([row[target] for row in training])
    for feature in features:
        if x_train[feature].isna().all():
            raise WorkerError(f"feature {feature} has no observed labeled values")
    return x_train, y_train, x_predict


def _tree_estimator(model: str, task: str, x_train):
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import OneHotEncoder
    from sklearn.tree import DecisionTreeClassifier, DecisionTreeRegressor
    from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor

    numerical = list(x_train.select_dtypes(include="number").columns)
    categorical = [name for name in x_train if name not in numerical]
    transformer = ColumnTransformer(
        [
            ("numerical", make_pipeline(SimpleImputer(strategy="median")), numerical),
            (
                "categorical",
                make_pipeline(
                    SimpleImputer(strategy="most_frequent"),
                    OneHotEncoder(handle_unknown="ignore"),
                ),
                categorical,
            ),
        ]
    )
    estimators = {
        ("decision_tree", "classification"): DecisionTreeClassifier,
        ("decision_tree", "regression"): DecisionTreeRegressor,
        ("random_forest", "classification"): RandomForestClassifier,
        ("random_forest", "regression"): RandomForestRegressor,
    }
    return make_pipeline(transformer, estimators[(model, task)](random_state=42))


def execute(request: dict[str, Any]) -> dict[str, Any]:
    model = request.get("model")
    task = request.get("task")
    if model not in MODELS or task not in TASKS:
        raise WorkerError("model or task is unsupported")
    x_train, y_train, x_predict = _frame(request)
    if task == "regression" and (not y_train.map(lambda value: isinstance(value, (int, float)) and not isinstance(value, bool)).all()):
        raise WorkerError("regression targets must be numeric")
    estimator = _tree_estimator(model, task, x_train)
    estimator.fit(x_train, y_train)
    predictions = estimator.predict(x_predict).tolist()
    confidence = (
        estimator.predict_proba(x_predict).max(axis=1).tolist()
        if task == "classification"
        else [None] * len(predictions)
    )
    return {
        "predictions": predictions,
        "confidence": confidence,
        "training_rows": len(x_train),
        "prediction_rows": len(x_predict),
        "context_rows": len(x_train),
    }


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise WorkerError("request must be an object")
        response = execute(request)
        print(json.dumps({"ok": True, "result": response}, allow_nan=False))
        return 0
    except (WorkerError, ImportError, ValueError, TypeError, OSError, RuntimeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
