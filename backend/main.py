
import logging
import re

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ml.predict import predict_message

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
