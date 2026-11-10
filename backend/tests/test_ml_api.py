from fastapi.testclient import TestClient

import main
from ml.predict import CLASSIFIER_PATH, VECTORIZER_PATH, predict_message

client = TestClient(main.app)


def test_existing_home_and_health_endpoints_remain_available() -> None:
    assert client.get("/").status_code == 200
    assert client.get("/health").json()["status"] == "healthy"


def test_empty_message_is_rejected() -> None:
    response = client.post("/api/analyze-message", json={"message": "   "})

    assert response.status_code == 422


def test_normal_message_prediction() -> None:
    prediction = predict_message(
        "Hi, are we still meeting for lunch tomorrow?"
    )

    assert prediction["predicted_label"] == "legitimate"
    assert 0.0 <= prediction["model_probability"] <= 1.0


def test_training_created_both_model_files() -> None:
    assert CLASSIFIER_PATH.is_file()
    assert VECTORIZER_PATH.is_file()


def test_spam_like_message_prediction() -> None:
    prediction = predict_message(
        "Congratulations! You have won a free gift. Claim now."
    )

    assert prediction["predicted_label"] == "spam"
    assert 0.0 <= prediction["model_probability"] <= 1.0


def test_analyze_endpoint_response_format() -> None:
    response = client.post(
        "/api/analyze-message",
        json={"message": "Your account is blocked. Click this link immediately."},
    )

    assert response.status_code == 200
    result = response.json()
    assert set(result) == {
        "predicted_label",
        "risk_level",
        "model_probability",
        "explanation",
        "warning_signs",
        "recommendations",
    }
    assert result["predicted_label"] in {"legitimate", "spam"}
    assert result["risk_level"] in {"elevated", "unconfirmed"}
    assert 0.0 <= result["model_probability"] <= 1.0
    assert result["warning_signs"]
    assert result["recommendations"]
    assert "not" in result["explanation"].lower()


def test_missing_model_returns_service_unavailable(monkeypatch) -> None:
    def missing_model(_message: str) -> dict[str, str | float]:
        raise FileNotFoundError("model files missing")

    monkeypatch.setattr(main, "predict_message", missing_model)
    response = client.post(
        "/api/analyze-message",
        json={"message": "A message that needs review."},
    )

    assert response.status_code == 503
    assert "model is not available" in response.json()["detail"]
