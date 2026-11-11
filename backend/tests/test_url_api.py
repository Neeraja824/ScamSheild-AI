from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


def test_valid_https_url_is_returned_as_unverified() -> None:
    response = client.post(
        "/api/analyze-url",
        json={"url": "https://example.com/account"},
    )

    assert response.status_code == 200
    result = response.json()
    assert set(result) == {
        "risk_level",
        "risk_indicators",
        "explanation",
        "warning_signs",
        "recommendations",
    }
    assert result["risk_level"] == "unverified"
    assert result["risk_indicators"] == []
    assert "unverified" in result["explanation"].lower()
    assert "not a complete phishing detector" in result["explanation"].lower()
    assert result["warning_signs"] == []
    assert result["recommendations"]


def test_valid_http_url_is_accepted() -> None:
    response = client.post(
        "/api/analyze-url",
        json={"url": "http://example.org"},
    )

    assert response.status_code == 200
    assert response.json()["risk_level"] == "unverified"


def test_invalid_url_has_clear_validation_error() -> None:
    response = client.post(
        "/api/analyze-url",
        json={"url": "ftp://example.com"},
    )

    assert response.status_code == 422
    assert "HTTP or HTTPS" in response.json()["detail"][0]["msg"]


def test_invalid_hostname_is_rejected() -> None:
    response = client.post(
        "/api/analyze-url",
        json={"url": "https://-example.com"},
    )

    assert response.status_code == 422
    assert "valid hostname" in response.json()["detail"][0]["msg"]


def test_empty_url_is_rejected() -> None:
    for submitted_url in ("", "   "):
        response = client.post(
            "/api/analyze-url",
            json={"url": submitted_url},
        )

        assert response.status_code == 422
        assert "must not be empty or whitespace" in response.json()["detail"][0]["msg"]


def test_suspicious_looking_url_returns_patterns_without_claiming_maliciousness() -> None:
    response = client.post(
        "/api/analyze-url",
        json={"url": "http://user@evil.login.secure.account.example.com/path"},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["risk_level"] == "caution"
    assert {
        "at_symbol_in_authority",
        "excessive_subdomains",
        "account_related_hostname",
    }.issubset(result["risk_indicators"])
    assert result["warning_signs"]
    assert "do not prove it is malicious" in result["explanation"]
    assert "unverified" in result["explanation"]


def test_ip_address_host_is_reported_as_a_pattern() -> None:
    response = client.post(
        "/api/analyze-url",
        json={"url": "http://192.0.2.1/"},
    )

    assert response.status_code == 200
    result = response.json()
    assert "ip_address_host" in result["risk_indicators"]
    assert any("IP address" in warning for warning in result["warning_signs"])


def test_shortened_url_is_flagged_without_resolving_its_destination() -> None:
    response = client.post(
        "/api/analyze-url",
        json={"url": "https://bit.ly/abc123"},
    )

    assert response.status_code == 200
    result = response.json()
    assert "url_shortener" in result["risk_indicators"]
    assert any("destination" in item for item in result["warning_signs"])


def test_existing_message_endpoint_still_works() -> None:
    response = client.post(
        "/api/analyze-message",
        json={"message": "Hi, are we still meeting for lunch tomorrow?"},
    )

    assert response.status_code == 200
    assert response.json()["predicted_label"] == "legitimate"
