"""Reusable prediction helpers for the SMS spam classifier."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib

BACKEND_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = BACKEND_DIR / "models"
CLASSIFIER_PATH = MODEL_DIR / "sms_spam_classifier.joblib"
VECTORIZER_PATH = MODEL_DIR / "sms_tfidf_vectorizer.joblib"
URL_PATTERN = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
WHITESPACE_PATTERN = re.compile(r"\s+")


def clean_message(message: str) -> str:
    """Normalize SMS text while retaining a marker for URLs."""
    normalized = URL_PATTERN.sub(" URL ", message)
    return WHITESPACE_PATTERN.sub(" ", normalized).strip().lower()


@lru_cache(maxsize=1)
def _load_artifacts() -> tuple[Any, Any]:
    missing = [
        path.name
        for path in (CLASSIFIER_PATH, VECTORIZER_PATH)
        if not path.is_file()
    ]
    if missing:
        raise FileNotFoundError(
            "Trained SMS model files are missing: "
            f"{', '.join(missing)}. Run `python -m ml.train_model` after preparing "
            "the UCI dataset."
        )
    return joblib.load(CLASSIFIER_PATH), joblib.load(VECTORIZER_PATH)


def predict_message(
    message: str,
    *,
    classifier: Any | None = None,
    vectorizer: Any | None = None,
) -> dict[str, str | float]:
    """Return the predicted SMS class and confidence in that selected class."""
    if not isinstance(message, str):
        raise TypeError("message must be a string.")
    normalized_message = message.strip()
    if not normalized_message:
        raise ValueError("message must not be empty.")
    if len(normalized_message) > 5000:
        raise ValueError("message must be 5000 characters or fewer.")
    if (classifier is None) != (vectorizer is None):
        raise ValueError("classifier and vectorizer must be provided together.")

    if classifier is None or vectorizer is None:
        classifier, vectorizer = _load_artifacts()

    features = vectorizer.transform([normalized_message])
    predicted_class = str(classifier.predict(features)[0])
    if predicted_class not in {"spam", "legitimate"}:
        raise ValueError("The loaded model returned an unsupported class.")

    probabilities = classifier.predict_proba(features)[0]
    classes = list(classifier.classes_)
    try:
        probability = float(probabilities[classes.index(predicted_class)])
    except (ValueError, IndexError) as error:
        raise ValueError("The loaded model returned an invalid probability result.") from error

    return {
        "predicted_label": predicted_class,
        "model_probability": probability,
    }
