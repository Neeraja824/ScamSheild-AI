"""Download and validate the UCI SMS Spam Collection dataset."""

from __future__ import annotations

import argparse
import io
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import pandas as pd

DATASET_URL = (
    "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
)
BACKEND_DIR = Path(__file__).resolve().parents[1]
DATASET_DIR = BACKEND_DIR / "datasets"
ARCHIVE_PATH = DATASET_DIR / "sms-spam-collection.zip"
PREPARED_PATH = DATASET_DIR / "sms_spam_collection.csv"
DATASET_MEMBER = "SMSSpamCollection"
VALID_LABELS = {"ham", "spam"}


def download_archive(force: bool = False) -> Path:
    """Download the real UCI archive, without leaving a partial file behind."""
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    if ARCHIVE_PATH.exists() and not force:
        print(f"Using existing dataset archive: {ARCHIVE_PATH}")
        return ARCHIVE_PATH

    request = urllib.request.Request(
        DATASET_URL,
        headers={"User-Agent": "ScamShield-AI-dataset-preparation/1.0"},
    )
    temporary_path: Path | None = None
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=DATASET_DIR, suffix=".download", delete=False
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                while chunk := response.read(1024 * 1024):
                    temporary_file.write(chunk)

        with zipfile.ZipFile(temporary_path) as archive:
            if DATASET_MEMBER not in archive.namelist():
                raise ValueError(
                    f"Downloaded archive does not contain {DATASET_MEMBER}."
                )
            if archive.testzip() is not None:
                raise ValueError("Downloaded dataset archive failed its integrity check.")

        temporary_path.replace(ARCHIVE_PATH)
        print(f"Downloaded UCI SMS Spam Collection to: {ARCHIVE_PATH}")
        return ARCHIVE_PATH
    except (OSError, urllib.error.URLError, zipfile.BadZipFile, ValueError) as error:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise RuntimeError(
            "Could not download or validate the UCI SMS Spam Collection. "
            "Check your network connection and try again; no training data was generated."
        ) from error


def prepare_dataset(archive_path: Path = ARCHIVE_PATH) -> Path:
    """Read the UCI TSV, drop invalid rows, and write a normalized CSV."""
    try:
        with zipfile.ZipFile(archive_path) as archive:
            if DATASET_MEMBER not in archive.namelist():
                raise ValueError(f"Archive is missing {DATASET_MEMBER}.")
            raw_data = archive.read(DATASET_MEMBER).decode("utf-8-sig", errors="replace")
    except (OSError, zipfile.BadZipFile, ValueError) as error:
        raise RuntimeError(
            f"Could not read the UCI dataset archive at {archive_path}."
        ) from error

    records: list[dict[str, str]] = []
    invalid_rows = 0
    for line in raw_data.splitlines():
        parts = line.split("\t", maxsplit=1)
        if len(parts) != 2:
            invalid_rows += 1
            continue

        label = parts[0].strip().lower()
        message = parts[1].strip()
        if label not in VALID_LABELS or not message:
            invalid_rows += 1
            continue
        records.append({"label": label, "message": message})

    if not records:
        raise ValueError(
            "The UCI dataset contained no valid SMS records; no CSV was created."
        )

    dataset = pd.DataFrame.from_records(records, columns=["label", "message"])
    before_deduplication = len(dataset)
    dataset = dataset.drop_duplicates(subset=["label", "message"]).reset_index(drop=True)
    duplicate_rows = before_deduplication - len(dataset)

    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    csv_buffer = io.StringIO()
    dataset.to_csv(csv_buffer, index=False)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=DATASET_DIR,
            suffix=".csv.tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(csv_buffer.getvalue())
        temporary_path.replace(PREPARED_PATH)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise

    print(f"Prepared {len(dataset)} valid records at: {PREPARED_PATH}")
    print(f"Dropped {invalid_rows} invalid and {duplicate_rows} duplicate records.")
    print(f"Class counts: {dataset['label'].value_counts().to_dict()}")
    return PREPARED_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Download a fresh copy instead of reusing the existing archive.",
    )
    arguments = parser.parse_args()
    archive_path = download_archive(force=arguments.force_download)
    prepare_dataset(archive_path)


if __name__ == "__main__":
    main()
