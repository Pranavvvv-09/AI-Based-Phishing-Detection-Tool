import io

import pytest

from phishguard import ocr

Image = pytest.importorskip("PIL.Image", reason="needs the OCR extra (Pillow)")


def encode(image, fmt="PNG"):
    buffer = io.BytesIO()
    image.save(buffer, format=fmt)
    return buffer.getvalue()


def test_accepts_png_jpeg_webp_and_scales_large_screenshots_down():
    for fmt in ("PNG", "JPEG", "WEBP"):
        image = ocr.load_image(encode(Image.new("RGB", (1080, 2400), "white"), fmt))
        assert image.mode == "RGB" and max(image.size) <= ocr.MAX_OCR_SIDE
    big = ocr.load_image(encode(Image.new("L", (3000, 6000), 255)))
    assert big.size == (1200, 2400)


@pytest.mark.parametrize("data", [b"", b"not an image", b"%PDF-1.7\n", b"\x89PNG\r\n\x1a\n"])
def test_rejects_what_is_not_an_image(data):
    with pytest.raises(ocr.ImageError):
        ocr.load_image(data)


def test_rejects_formats_outside_the_allow_list_whatever_the_name():
    for fmt in ("GIF", "BMP", "TIFF"):
        with pytest.raises(ocr.ImageError, match="PNG, JPEG or WebP"):
            ocr.load_image(encode(Image.new("RGB", (40, 40)), fmt))


def test_rejects_oversize_files_before_decoding(monkeypatch):
    monkeypatch.setattr(ocr, "MAX_IMAGE_BYTES", 100)
    with pytest.raises(ocr.ImageError, match="larger than"):
        ocr.load_image(encode(Image.new("RGB", (200, 200), "white")) + b"\0" * 100)


def test_rejects_decompression_bombs_from_the_header_alone():
    # 6000 x 5000 = 30 MP of one colour compresses to a few kB; refused before decoding.
    bomb = encode(Image.new("L", (6000, 5000), 0))
    assert len(bomb) < ocr.MAX_IMAGE_BYTES
    with pytest.raises(ocr.ImageError, match="too many pixels"):
        ocr.load_image(bomb)


def test_rejects_truncated_images():
    data = encode(Image.new("RGB", (400, 400), "white"), "JPEG")
    with pytest.raises(ocr.ImageError):
        ocr.load_image(data[: len(data) // 2])


def test_reads_the_text_of_a_screenshot():
    pytest.importorskip("rapidocr", reason="needs the OCR extra (RapidOCR)")
    from PIL import ImageDraw, ImageFont

    image = Image.new("RGB", (900, 200), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=32)
    draw.text((20, 30), "Your SBI account is blocked.", fill="black", font=font)
    draw.text((20, 110), "Update KYC at sbi-kyc-update.in", fill="black", font=font)
    text = ocr.extract_text(encode(image))
    assert "SBI account is blocked" in text and "KYC" in text
    assert text.count("\n") == 1  # one line per line of text, top to bottom
