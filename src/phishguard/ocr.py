"""Read the text of an SMS screenshot, so Quick Scan can score it like a pasted SMS.

Optional: needs ``pip install -e ".[ocr]"`` (RapidOCR on onnxruntime). The OCR models
ship inside the ``rapidocr`` wheel, so reading an image needs no network, like the rest
of PhishGuard.

Every upload is treated as hostile input:

* The byte size is checked before anything is decoded.
* Only PNG, JPEG and WebP are accepted, judged by the file's content, not its name.
* The pixel count is read from the header and checked *before* decoding, so a small
  file that claims to be a 100000 x 100000 image (a "decompression bomb") is rejected
  without allocating memory for it.
* Large screenshots are scaled down before OCR to bound the time it takes.
* The image is never stored; only the text read from it is returned.
"""

from __future__ import annotations

import io
import threading

import numpy as np

MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000  # a 1440 x 3200 phone screenshot is 4.6 MP
MAX_OCR_SIDE = 2400  # longest side fed to OCR; phone screenshots stay sharp at this size
MIN_CONFIDENCE = 0.5  # lines the OCR is less sure of are mostly icons and noise
ALLOWED_FORMATS = frozenset({"PNG", "JPEG", "WEBP"})

_engine = None
_lock = threading.Lock()


class ImageError(ValueError):
    """The upload is not a usable image (wrong type, too large, corrupt)."""


class OCRUnavailable(RuntimeError):
    """The optional OCR packages are not installed."""


def load_image(data: bytes):
    """Validate ``data`` and return it as an RGB Pillow image, scaled down if large."""
    try:
        from PIL import Image
    except ImportError:
        raise OCRUnavailable("install the OCR extra: pip install -e \".[ocr]\"") from None
    if not data:
        raise ImageError("The image is empty.")
    if len(data) > MAX_IMAGE_BYTES:
        raise ImageError(f"The image is larger than {MAX_IMAGE_BYTES // (1024 * 1024)} MB.")
    try:
        image = Image.open(io.BytesIO(data))  # reads the header only
    except (OSError, ValueError, SyntaxError, Image.DecompressionBombError):
        raise ImageError("That file is not a PNG, JPEG or WebP image.") from None
    if image.format not in ALLOWED_FORMATS:
        raise ImageError("That file is not a PNG, JPEG or WebP image.")
    width, height = image.size
    if width * height > MAX_IMAGE_PIXELS:
        raise ImageError("The image has too many pixels; send a normal screenshot.")
    try:
        image.load()
    except (OSError, ValueError, SyntaxError, Image.DecompressionBombError):
        raise ImageError("The image is damaged and could not be read.") from None
    image = image.convert("RGB")
    image.thumbnail((MAX_OCR_SIDE, MAX_OCR_SIDE))  # only ever shrinks
    return image


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from rapidocr import RapidOCR
        except ImportError:
            raise OCRUnavailable("install the OCR extra: pip install -e \".[ocr]\"") from None
        _engine = RapidOCR()
    return _engine


def extract_text(data: bytes) -> str:
    """The text in an image, one line per detected line, top to bottom."""
    image = load_image(data)
    with _lock:  # one OCR at a time: bounded CPU and memory, and the engine is shared
        result = _get_engine()(np.asarray(image))
    found = zip(result.txts or (), result.scores or (), strict=True)
    lines = [text.strip() for text, score in found if score >= MIN_CONFIDENCE and text.strip()]
    return "\n".join(lines)
