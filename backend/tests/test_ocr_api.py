from io import BytesIO

import pytesseract
from fastapi.testclient import TestClient
from PIL import Image

import main

client = TestClient(main.app)


def make_image_bytes(image_format: str = "PNG") -> bytes:
    image = Image.new("RGB", (20, 20), color="white")
    output = BytesIO()
    image.save(output, format=image_format)
    return output.getvalue()


def test_extract_text_from_supported_image(monkeypatch) -> None:
    monkeypatch.setattr(
        pytesseract,
        "image_to_string",
        lambda _image, lang, timeout: "  Screenshot text\nwith a link: https://example.com  ",
    )
    response = client.post(
        "/api/extract-text",
        files={"file": ("screenshot.webp", make_image_bytes("WEBP"), "application/octet-stream")},
    )

    assert response.status_code == 200
    assert response.json() == {
        "success": True,
        "extracted_text": "Screenshot text\nwith a link: https://example.com",
        "message": "Text extracted successfully.",
    }


def test_empty_upload_is_rejected() -> None:
    response = client.post(
        "/api/extract-text",
        files={"file": ("empty.png", b"", "image/png")},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "The uploaded image is empty."


def test_invalid_image_bytes_are_rejected() -> None:
    response = client.post(
        "/api/extract-text",
        files={"file": ("image.png", b"not an image", "image/png")},
    )

    assert response.status_code == 400
    assert "not a readable" in response.json()["detail"]


def test_unsupported_actual_image_format_is_rejected() -> None:
    response = client.post(
        "/api/extract-text",
        files={"file": ("image.png", make_image_bytes("GIF"), "image/png")},
    )

    assert response.status_code == 415
    assert "Unsupported image format" in response.json()["detail"]


def test_oversized_upload_is_rejected_before_image_processing(monkeypatch) -> None:
    def should_not_process(_image_bytes: bytes) -> str:
        raise AssertionError("Oversized upload should not be processed.")

    monkeypatch.setattr(main, "_extract_english_text", should_not_process)
    response = client.post(
        "/api/extract-text",
        files={
            "file": (
                "oversized.png",
                b"x" * (main.MAX_IMAGE_UPLOAD_SIZE + 1),
                "image/png",
            )
        },
    )

    assert response.status_code == 413
    assert "5 MB" in response.json()["detail"]


def test_missing_tesseract_executable_returns_service_unavailable(monkeypatch) -> None:
    def tesseract_not_found(_image, *, lang: str, timeout: int) -> str:
        raise pytesseract.TesseractNotFoundError()

    monkeypatch.setattr(pytesseract, "image_to_string", tesseract_not_found)
    response = client.post(
        "/api/extract-text",
        files={"file": ("screenshot.png", make_image_bytes(), "image/png")},
    )

    assert response.status_code == 503
    assert "Tesseract OCR is not installed" in response.json()["detail"]


def test_image_without_readable_text_returns_clear_error(monkeypatch) -> None:
    monkeypatch.setattr(pytesseract, "image_to_string", lambda *_args, **_kwargs: " \n ")
    response = client.post(
        "/api/extract-text",
        files={"file": ("blank.png", make_image_bytes(), "image/png")},
    )

    assert response.status_code == 422
    assert "No readable English text" in response.json()["detail"]
