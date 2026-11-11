
import logging
import re
from io import BytesIO
from typing import Literal

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool

from ml.predict import predict_message
from url_analysis import URLAnalysis, analyze_url, validate_http_url

logger = logging.getLogger(__name__)

app = FastAPI(
    title="ScamShield AI",
    description="An SMS spam classifier to support safer, more informed decisions.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "ScamShield AI Backend is Running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "ScamShield AI"
    }


class AnalyzeMessageRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    message: str = Field(min_length=1, max_length=5000)

    @field_validator("message")
    @classmethod
    def message_must_contain_text(cls, value: str) -> str:
        if not value:
            raise ValueError("message must not be empty or whitespace.")
        return value


class AnalyzeMessageResponse(BaseModel):
    predicted_label: str
    risk_level: str
    model_probability: float
    explanation: str
    warning_signs: list[str]
    recommendations: list[str]


class AnalyzeURLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url", mode="before")
    @classmethod
    def url_must_not_be_empty(cls, value: object) -> object:
        if isinstance(value, str):
            normalized_url = value.strip()
            if not normalized_url:
                raise ValueError("URL must not be empty or whitespace.")
            return normalized_url
        return value

    @field_validator("url")
    @classmethod
    def url_must_be_http_or_https(cls, value: str) -> str:
        return validate_http_url(value)


class AnalyzeURLResponse(BaseModel):
    risk_level: Literal["unverified", "caution"]
    risk_indicators: list[str]
    explanation: str
    warning_signs: list[str]
    recommendations: list[str]


class ExtractTextResponse(BaseModel):
    success: bool
    extracted_text: str
    message: str


MAX_IMAGE_UPLOAD_SIZE = 5 * 1024 * 1024
SUPPORTED_IMAGE_FORMATS = frozenset({"PNG", "JPEG", "WEBP"})


class OCRDependencyError(RuntimeError):
    """Raised when optional Python OCR dependencies are unavailable."""


class OCRExecutableNotFoundError(RuntimeError):
    """Raised when the Tesseract executable cannot be located."""


class InvalidImageError(ValueError):
    """Raised when uploaded bytes do not contain a readable supported image."""


class UnsupportedImageFormatError(ValueError):
    """Raised when the decoded image format is not supported for OCR."""


class NoTextFoundError(ValueError):
    """Raised when OCR produces no readable text."""


class OCRProcessingError(RuntimeError):
    """Raised when Tesseract cannot process an otherwise valid image."""


def _extract_english_text(image_bytes: bytes) -> str:
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as error:
        raise OCRDependencyError(
            "Image OCR dependencies are unavailable. Install the backend requirements."
        ) from error

    try:
        import pytesseract
    except ImportError as error:
        raise OCRDependencyError(
            "Image OCR dependencies are unavailable. Install the backend requirements."
        ) from error

    try:
        with Image.open(BytesIO(image_bytes)) as image:
            image_format = image.format
            if image_format not in SUPPORTED_IMAGE_FORMATS:
                raise UnsupportedImageFormatError(
                    "Unsupported image format. Upload a PNG, JPG, JPEG, or WEBP image."
                )
            image.verify()
        with Image.open(BytesIO(image_bytes)) as image:
            extracted_text = pytesseract.image_to_string(
                image,
                lang="eng",
                timeout=15,
            ).strip()
    except UnsupportedImageFormatError:
        raise
    except pytesseract.TesseractNotFoundError as error:
        raise OCRExecutableNotFoundError(
            "Tesseract OCR is not installed or is not available on the server PATH."
        ) from error
    except pytesseract.TesseractError as error:
        raise OCRProcessingError(
            "Tesseract could not read this image. Try a clearer PNG, JPG, or WEBP image."
        ) from error
    except (
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as error:
        raise InvalidImageError(
            "The uploaded file is not a readable PNG, JPG, JPEG, or WEBP image."
        ) from error

    if not extracted_text:
        raise NoTextFoundError("No readable English text was found in the image.")
    return extracted_text


WARNING_SIGN_RULES = (
    (re.compile(r"\b(?:urgent|immediately|act now|asap|final notice)\b", re.I),
     "Uses urgent or pressure-driven language."),
    (re.compile(r"\b(?:click|tap|visit|open)\b.{0,30}\b(?:link|url|website)\b", re.I),
     "Asks you to follow a link."),
    (re.compile(r"(?:https?://|www\.)\S+", re.I),
     "Contains a web address."),
    (re.compile(r"\b(?:password|passcode|one[- ]time code|verification code|pin)\b", re.I),
     "Mentions credentials or verification codes."),
    (re.compile(r"\b(?:bank|account|card)\b.{0,35}\b(?:blocked|suspended|locked|closed)\b", re.I),
     "Claims an account or payment method is blocked or suspended."),
    (re.compile(r"\b(?:won|winner|prize|claim your reward|free gift)\b", re.I),
     "Mentions a prize, reward, or unexpected gift."),
)


def _find_warning_signs(message: str) -> list[str]:
    return [description for pattern, description in WARNING_SIGN_RULES if pattern.search(message)]


@app.post(
    "/api/analyze-message",
    response_model=AnalyzeMessageResponse,
    summary="Classify a message with the SMS spam model",
)
def analyze_message(request: AnalyzeMessageRequest) -> AnalyzeMessageResponse:
    """Classify SMS-like text; this does not verify that a message is safe."""
    try:
        prediction = predict_message(request.message)
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=503,
            detail=(
                "The SMS spam model is not available. Prepare the UCI dataset and "
                "train the model before using this endpoint."
            ),
        ) from error
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        logger.exception("Unexpected error while analyzing a message.")
        raise HTTPException(
            status_code=500,
            detail="Message analysis failed unexpectedly. Please try again later.",
        ) from error

    predicted_label = str(prediction["predicted_label"])
    model_probability = float(prediction["model_probability"])
    warning_signs = _find_warning_signs(request.message)

    if predicted_label == "spam":
        risk_level = "elevated"
        explanation = (
            "The SMS spam classifier flagged this message as spam. Its model "
            "confidence is based on patterns learned from the UCI SMS Spam "
            "Collection; it is not a guaranteed probability that this message is "
            "a scam. This classifier may miss scams outside its training domain."
        )
    else:
        risk_level = "unconfirmed"
        explanation = (
            "The SMS spam classifier did not flag this message as spam. That does "
            "not confirm the message is legitimate or safe: this model only "
            "recognizes patterns in the UCI SMS Spam Collection and may miss other "
            "scams. Its model confidence is not a probability that this message "
            "is legitimate."
        )

    recommendations = [
        "Do not share passwords, payment details, or verification codes in response to an unexpected message.",
        "Verify unusual requests using a phone number or website you find independently, not details in the message.",
    ]
    if warning_signs:
        recommendations.insert(
            0, "Pause before responding or following any instructions in the message."
        )
    else:
        recommendations.insert(
            0, "Review the message carefully; an absence of common warning signs is not proof it is safe."
        )

    return AnalyzeMessageResponse(
        predicted_label=predicted_label,
        risk_level=risk_level,
        model_probability=model_probability,
        explanation=explanation,
        warning_signs=warning_signs,
        recommendations=recommendations,
    )


@app.post(
    "/api/analyze-url",
    response_model=AnalyzeURLResponse,
    summary="Review URL format and basic suspicious patterns without visiting it",
)
def analyze_submitted_url(request: AnalyzeURLRequest) -> AnalyzeURLResponse:
    """Review URL structure locally; this endpoint never opens or verifies the URL."""
    analysis: URLAnalysis = analyze_url(request.url)
    return AnalyzeURLResponse(**analysis)


@app.post(
    "/api/extract-text",
    response_model=ExtractTextResponse,
    summary="Extract English text from an uploaded screenshot",
)
async def extract_text(file: UploadFile = File(...)) -> ExtractTextResponse:
    """Extract text from an in-memory image; links in the image are never opened."""
    try:
        image_bytes = await file.read(MAX_IMAGE_UPLOAD_SIZE + 1)
        if not image_bytes:
            raise HTTPException(
                status_code=422,
                detail="The uploaded image is empty.",
            )
        if len(image_bytes) > MAX_IMAGE_UPLOAD_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Image upload exceeds the 5 MB size limit.",
            )

        try:
            extracted_text = await run_in_threadpool(_extract_english_text, image_bytes)
        except UnsupportedImageFormatError as error:
            raise HTTPException(status_code=415, detail=str(error)) from error
        except InvalidImageError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        except NoTextFoundError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except OCRExecutableNotFoundError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        except OCRDependencyError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        except OCRProcessingError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

        return ExtractTextResponse(
            success=True,
            extracted_text=extracted_text,
            message="Text extracted successfully.",
        )
    finally:
        await file.close()
