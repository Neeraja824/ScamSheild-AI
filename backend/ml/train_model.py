"""Train and evaluate the TF-IDF Logistic Regression SMS classifier."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from ml.predict import clean_message
from ml.prepare_dataset import PREPARED_PATH

BACKEND_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = BACKEND_DIR / "models"
CLASSIFIER_PATH = MODEL_DIR / "sms_spam_classifier.joblib"
VECTORIZER_PATH = MODEL_DIR / "sms_tfidf_vectorizer.joblib"
RANDOM_STATE = 42


def _save_artifact(value: object, destination: Path) -> None:
    """Write an artifact atomically so an interrupted run cannot leave it partial."""
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, suffix=".joblib.tmp", delete=False
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
        joblib.dump(value, temporary_path)
        temporary_path.replace(destination)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def train_model(dataset_path: Path = PREPARED_PATH) -> dict[str, object]:
    if not dataset_path.is_file():
        raise FileNotFoundError(
            f"Prepared UCI dataset not found at {dataset_path}. "
            "Run `python -m ml.prepare_dataset` first; no fallback data is used."
        )

    dataset = pd.read_csv(dataset_path, dtype={"label": "string", "message": "string"})
    required_columns = {"label", "message"}
    if not required_columns.issubset(dataset.columns):
        raise ValueError("Prepared dataset must contain label and message columns.")

    dataset = dataset.dropna(subset=["label", "message"]).copy()
    dataset["label"] = dataset["label"].str.strip().str.lower().replace(
        {"ham": "legitimate"}
    )
    dataset["message"] = dataset["message"].astype(str).str.strip()
    dataset = dataset[
        dataset["label"].isin(["legitimate", "spam"]) & dataset["message"].ne("")
    ]
    if dataset["label"].nunique() != 2:
        raise ValueError("Training data must include both ham and spam records.")
    if dataset["label"].value_counts().min() < 2:
        raise ValueError("Each class needs at least two records for stratified splitting.")

    messages = dataset["message"]
    labels = dataset["label"]
    x_train, x_test, y_train, y_test = train_test_split(
        messages,
        labels,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=labels,
    )

    vectorizer = TfidfVectorizer(
        preprocessor=clean_message,
        lowercase=False,
        ngram_range=(1, 2),
        min_df=1,
        max_features=50_000,
    )
    train_features = vectorizer.fit_transform(x_train)
    test_features = vectorizer.transform(x_test)

    classifier = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    classifier.fit(train_features, y_train)
    predictions = classifier.predict(test_features)

    metrics: dict[str, object] = {
        "test_records": int(len(y_test)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision_spam": float(
            precision_score(y_test, predictions, pos_label="spam", zero_division=0)
        ),
        "recall_spam": float(
            recall_score(y_test, predictions, pos_label="spam", zero_division=0)
        ),
        "f1_spam": float(f1_score(y_test, predictions, pos_label="spam", zero_division=0)),
        "confusion_matrix_labels": ["legitimate", "spam"],
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=["legitimate", "spam"]
        ).tolist(),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    _save_artifact(classifier, CLASSIFIER_PATH)
    _save_artifact(vectorizer, VECTORIZER_PATH)

    print("Evaluation on the stratified held-out test split:")
    print(json.dumps(metrics, indent=2))
    print(f"Classifier saved to: {CLASSIFIER_PATH}")
    print(f"TF-IDF vectorizer saved to: {VECTORIZER_PATH}")
    return metrics


if __name__ == "__main__":
    train_model()
