import json
import pytest
from fastapi.testclient import TestClient

import main
import scan_history


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    database_path = tmp_path / "scan-history.sqlite3"
    monkeypatch.setenv("SCAMSHIELD_HISTORY_DB_PATH", str(database_path))
    scan_history.initialize_database()
    with TestClient(main.app) as test_client:
        yield test_client


def _mock_prediction(monkeypatch, label: str = "spam") -> None:
    monkeypatch.setattr(
        main,
        "predict_message",
        lambda _message: {
            "predicted_label": label,
            "model_probability": 0.91,
        },
    )


def test_message_url_and_screenshot_scans_are_recorded_without_input_text(
    client: TestClient,
    monkeypatch,
) -> None:
    _mock_prediction(monkeypatch)
    message = "private message text unique-marker-129"
    screenshot_text = "private OCR text unique-marker-832"
    submitted_url = "https://private.example/path?token=unique-marker-773"

    message_response = client.post("/api/analyze-message", json={"message": message})
    url_response = client.post("/api/analyze-url", json={"url": submitted_url})
    screenshot_response = client.post(
        "/api/analyze-screenshot",
        json={"extracted_text": screenshot_text},
    )

    assert message_response.status_code == 200
    assert set(message_response.json()) == {
        "predicted_label",
        "risk_level",
        "model_probability",
        "explanation",
        "warning_signs",
        "recommendations",
    }
    assert url_response.status_code == 200
    assert set(url_response.json()) == {
        "risk_level",
        "risk_indicators",
        "explanation",
        "warning_signs",
        "recommendations",
    }
    assert screenshot_response.status_code == 200
    assert screenshot_response.json() == message_response.json()

    history = client.get("/api/scan-history").json()
    assert history["total"] == 3
    assert {item["scan_type"] for item in history["items"]} == {
        "message",
        "url",
        "screenshot",
    }
    history_text = json.dumps(history)
    assert message not in history_text
    assert submitted_url not in history_text
    assert screenshot_text not in history_text

    details_by_type = {
        item["scan_type"]: client.get(
            f"/api/scan-history/{item['scan_id']}"
        ).json()
        for item in history["items"]
    }
    assert details_by_type["message"]["predicted_class"] == "spam"
    assert details_by_type["message"]["model_confidence"] == 0.91
    assert message not in json.dumps(details_by_type["message"])
    assert submitted_url not in json.dumps(details_by_type["url"])
    assert screenshot_text not in json.dumps(details_by_type["screenshot"])
    assert "character_count" in details_by_type["screenshot"]["details"]


def test_history_pagination_and_scan_type_filtering(client: TestClient, monkeypatch) -> None:
    _mock_prediction(monkeypatch, "legitimate")
    client.post("/api/analyze-message", json={"message": "first"})
    client.post("/api/analyze-url", json={"url": "https://one.example"})
    client.post("/api/analyze-screenshot", json={"extracted_text": "third"})

    first_page = client.get("/api/scan-history?limit=1&offset=0").json()
    second_page = client.get("/api/scan-history?limit=1&offset=1").json()
    messages = client.get("/api/scan-history?scan_type=message").json()
    screenshots = client.get("/api/scan-history?scan_type=screenshot").json()

    assert first_page["total"] == 3
    assert len(first_page["items"]) == 1
    assert len(second_page["items"]) == 1
    assert first_page["items"][0]["scan_id"] != second_page["items"][0]["scan_id"]
    assert messages["total"] == 1
    assert messages["items"][0]["scan_type"] == "message"
    assert screenshots["total"] == 1
    assert screenshots["items"][0]["scan_type"] == "screenshot"


def test_unknown_scan_id_returns_404(client: TestClient) -> None:
    response = client.get("/api/scan-history/not-a-scan-id")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan history record not found."


def test_clearing_history_returns_deleted_count_and_clears_dashboard(
    client: TestClient,
    monkeypatch,
) -> None:
    _mock_prediction(monkeypatch)
    client.post("/api/analyze-message", json={"message": "one"})
    client.post("/api/analyze-url", json={"url": "https://example.com"})

    response = client.delete("/api/scan-history")

    assert response.status_code == 200
    assert response.json() == {"deleted_count": 2}
    assert client.get("/api/scan-history").json()["total"] == 0
    assert client.get("/api/dashboard/summary").json()["total_scans"] == 0


def test_dashboard_summary_reports_counts_and_recent_scans(
    client: TestClient,
    monkeypatch,
) -> None:
    _mock_prediction(monkeypatch)
    client.post("/api/analyze-message", json={"message": "message"})
    client.post("/api/analyze-url", json={"url": "https://example.com"})
    client.post("/api/analyze-screenshot", json={"extracted_text": "screenshot"})

    response = client.get("/api/dashboard/summary")

    assert response.status_code == 200
    summary = response.json()
    assert summary["total_scans"] == 3
    assert summary["scan_type_counts"] == {
        "message": 1,
        "url": 1,
        "screenshot": 1,
    }
    assert sum(summary["risk_level_counts"].values()) == 3
    assert summary["latest_scan_at"].endswith("Z")
    assert len(summary["recent_scans"]) == 3


def test_database_records_persist_across_connections(client: TestClient) -> None:
    inserted = scan_history.insert_scan(
        scan_type="message",
        risk_level="unconfirmed",
        predicted_class="legitimate",
        model_confidence=0.73,
        warning_signs=[],
        recommendations=["Verify independently."],
        explanation="The classification is not proof of safety.",
        details={"character_count": 22},
    )

    retrieved = scan_history.get_scan(inserted["scan_id"])
    assert retrieved == inserted
    assert retrieved["timestamp"].endswith("Z")


def test_history_filter_and_pagination_validation(client: TestClient) -> None:
    assert client.get("/api/scan-history?scan_type=unknown").status_code == 422
    assert client.get("/api/scan-history?limit=101").status_code == 422
    assert client.get("/api/scan-history?offset=-1").status_code == 422


def test_each_scan_record_gets_a_unique_id(client: TestClient) -> None:
    first = scan_history.insert_scan(
        scan_type="url",
        risk_level="unverified",
        explanation="No checked patterns found; the URL remains unverified.",
        warning_signs=[],
        recommendations=[],
    )
    second = scan_history.insert_scan(
        scan_type="url",
        risk_level="unverified",
        explanation="No checked patterns found; the URL remains unverified.",
        warning_signs=[],
        recommendations=[],
    )

    assert first["scan_id"] != second["scan_id"]
