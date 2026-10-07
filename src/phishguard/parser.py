"""Safely parse raw ``.eml`` bytes into a structured, size-bounded ``ParsedEmail``.

Every email is treated as hostile input:

* The raw size, header-section size and number of MIME boundary lines are checked
  *before* parsing, because Python's parser does super-linear work on huge address
  lists and on tens of thousands of parts (measured: 1.5 MB took 90 s).
* Top-level headers are read as raw strings and truncated before any decoding or
  address parsing.
* MIME traversal is iterative, with caps on part count and nesting depth, so
  "MIME bombs" can't exhaust memory or the recursion limit.
* Decoded text is capped by a total character budget. base64 and quoted-printable
  always decode smaller than their encoded form, so the raw cap also bounds decoded
  bytes; the text budget bounds what later stages (regexes, ML) have to process.
* HTML is never rendered. It is tokenised with the stdlib ``HTMLParser`` only to pull
  out visible text and link targets; ``<script>`` and ``<style>`` contents are dropped.
* Attachment bytes are never stored or written to disk, only their metadata.
* Header values are stripped of control characters (CR/LF etc.) and truncated, so
  attacker-controlled headers can't inject fake lines into logs or reports.
* Message bodies are excluded from ``repr`` so logging a ``ParsedEmail`` can't leak
  email content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path

DEFAULT_MAX_BYTES = 5 * 1024 * 1024
MAX_PARTS = 100
MAX_DEPTH = 10
MAX_TEXT_CHARS = 200_000  # total budget across all text and HTML bodies
MAX_HTML_SOURCE_CHARS = 1_000_000  # HTML fed to the tokenizer (Gmail clips at ~102 KB)
MAX_HEADER_CHARS = 1_000
MAX_RAW_HEADER_CHARS = 16_384  # raw value is truncated to this before any parsing
MAX_HEADER_SECTION_BYTES = 256 * 1024
MAX_BOUNDARY_LINES = 2_000
MAX_HEADER_INSTANCES = 50  # e.g. Received headers
MAX_LINKS = 300
MAX_URL_CHARS = 2_048
MAX_ADDRESSES = 500

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")
_WHITESPACE_RUN = re.compile(r"\s{2,}")
# Linear-time URL pattern: one bounded character class, no nested quantifiers (no ReDoS).
_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'()\[\]{}]{1,2048}")
_TRAILING_PUNCT = ".,;:!?"
_BLOCK_TAGS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table"}
_SKIP_TAGS = {"script", "style", "head", "noscript", "template"}


class EmailParseError(ValueError):
    """The input could not be parsed as an email."""


class EmailLimitError(EmailParseError):
    """The input exceeds a safety limit (size, header section or MIME part count).

    This is *not* proof the message is harmless or malicious. Callers should route
    it to manual review (fail safe) rather than silently dropping or delivering it.
    """


class EmailTooLargeError(EmailLimitError):
    """The input exceeds the configured size limit."""


@dataclass(frozen=True)
class Link:
    href: str  # target exactly as written (never fetched or resolved)
    text: str  # visible anchor text ("" for bare URLs)
    source: str  # "html" (anchor), "form" (form action) or "text" (URL in body text)


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class ParsedEmail:
    subject: str = ""
    from_display: str = ""
    from_address: str = ""
    reply_to: list[str] = field(default_factory=list)
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    message_id: str = ""
    date: str = ""
    # Ordered top-most first: the first entry was added by the final receiving server.
    authentication_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    text_body: str = field(default="", repr=False)
    html_text: str = field(default="", repr=False)
    links: list[Link] = field(default_factory=list, repr=False)
    attachments: list[Attachment] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def recipient_count(self) -> int:
        return len(self.to) + len(self.cc)

    @property
    def body(self) -> str:
        """All visible text: plain-text body plus text extracted from HTML."""
        return "\n".join(part for part in (self.text_body, self.html_text) if part)


def clean_header(value: object, limit: int = MAX_HEADER_CHARS) -> str:
    """Turn control characters (including CR/LF) into spaces, collapse runs of
    whitespace (e.g. from folded headers) and truncate."""
    text = _CONTROL_CHARS.sub(" ", str(value))
    return _WHITESPACE_RUN.sub(" ", text).strip()[:limit]


class _HTMLExtractor(HTMLParser):
    """Collect visible text and link targets from HTML without rendering it."""

    def __init__(self, char_budget: int) -> None:
        super().__init__(convert_charrefs=True)
        self.char_budget = char_budget
        self.chunks: list[str] = []
        self.links: list[Link] = []
        self.truncated = False
        self._skip_depth = 0
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def _add_text(self, text: str) -> None:
        if self.char_budget <= 0:
            self.truncated = True
            return
        piece = text[: self.char_budget]
        self.char_budget -= len(piece)
        self.chunks.append(piece)
        if len(piece) < len(text):
            self.truncated = True

    def _add_link(self, href: str, text: str, source: str) -> None:
        if len(self.links) >= MAX_LINKS:
            self.truncated = True
            return
        self.links.append(
            Link(href=clean_header(href, MAX_URL_CHARS), text=clean_header(text), source=source)
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
            return
        if tag in _BLOCK_TAGS:
            self._add_text("\n")
        attributes = dict(attrs)
        if tag == "a" and attributes.get("href"):
            self._href = attributes["href"]
            self._anchor_text = []
        elif tag == "form" and attributes.get("action"):
            # Credential-harvesting forms embedded in the email itself.
            self._add_link(attributes["action"] or "", "", "form")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag == "a" and self._href is not None:
            self._add_link(self._href, " ".join(self._anchor_text), "html")
            self._href = None
            self._anchor_text = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._href is not None and sum(map(len, self._anchor_text)) < MAX_HEADER_CHARS:
            self._anchor_text.append(data.strip())
        self._add_text(data)

    def text(self) -> str:
        joined = "".join(self.chunks)
        return "\n".join(line.strip() for line in joined.splitlines() if line.strip())


def _decode_part(part: EmailMessage, result: ParsedEmail) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001 - malformed encodings must never crash parsing
        result.defects.append("undecodable_part")
        return ""
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        # bytes.decode only accepts *text* encodings, so attacker-chosen charsets such as
        # "zlib" or "base64" (binary codecs, e.g. decompression bombs) are rejected here.
        return payload.decode(charset, errors="replace")
    except (LookupError, ValueError):
        result.defects.append("unknown_charset")
        return payload.decode("utf-8", errors="replace")


def _raw_headers(msg: EmailMessage, name: str) -> list[str]:
    """Unparsed header values, unfolded and truncated *before* any further parsing."""
    name = name.lower()
    values = [
        str(value)[:MAX_RAW_HEADER_CHARS].replace("\r", "").replace("\n", "")
        for key, value in msg.raw_items()
        if key.lower() == name
    ]
    return values[:MAX_HEADER_INSTANCES]


def _decode_words(value: str) -> str:
    """Decode RFC 2047 encoded-words (=?utf-8?b?...?=); fall back to the raw text."""
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # noqa: BLE001 - unknown charsets / broken encodings
        return value


def _first(msg: EmailMessage, name: str) -> str:
    values = _raw_headers(msg, name)
    return values[0] if values else ""


def _addresses(msg: EmailMessage, name: str) -> list[str]:
    addrs = [clean_header(a).lower() for _, a in getaddresses(_raw_headers(msg, name)) if a]
    return addrs[:MAX_ADDRESSES]


def _header_list(msg: EmailMessage, name: str) -> list[str]:
    return [clean_header(v) for v in _raw_headers(msg, name)]


def extract_urls(text: str) -> list[str]:
    """Bare URLs in free text (email or SMS), bounded and linear-time."""
    urls = []
    for match in _URL_RE.finditer(text):
        urls.append(match.group(0).rstrip(_TRAILING_PUNCT))
        if len(urls) >= MAX_LINKS:
            break
    return urls


def _precheck(raw: bytes, max_header_bytes: int, max_boundary_lines: int) -> None:
    """Cheap structural limits applied before handing bytes to the stdlib parser."""
    ends = [i for i in (raw.find(b"\r\n\r\n"), raw.find(b"\n\n")) if i != -1]
    header_end = min(ends) if ends else len(raw)
    if header_end > max_header_bytes:
        raise EmailLimitError("header section too large")
    if raw.count(b"\n--") > max_boundary_lines:
        raise EmailLimitError("too many MIME parts")


def parse_email(
    raw: bytes,
    max_bytes: int = DEFAULT_MAX_BYTES,
    *,
    max_header_bytes: int = MAX_HEADER_SECTION_BYTES,
    max_boundary_lines: int = MAX_BOUNDARY_LINES,
) -> ParsedEmail:
    """Parse raw RFC 5322 bytes.

    Raises ``EmailLimitError`` (route to manual review) when a safety limit is hit,
    or ``EmailParseError`` when the input is not an email at all. The limits are
    generous for real mail; they can be raised per call for unusual mailboxes.
    """
    if not isinstance(raw, bytes | bytearray):
        raise TypeError("raw email must be bytes")
    if len(raw) > max_bytes:
        raise EmailTooLargeError(f"email exceeds {max_bytes} bytes")
    if not raw.strip():
        raise EmailParseError("email is empty")
    raw = bytes(raw)
    _precheck(raw, max_header_bytes, max_boundary_lines)

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # noqa: BLE001
        # Generic message: never echo email content back in errors.
        raise EmailParseError("could not parse email") from exc

    result = ParsedEmail()
    result.subject = clean_header(_decode_words(_first(msg, "Subject")))
    display, address = parseaddr(_first(msg, "From"))
    result.from_display = clean_header(_decode_words(display))
    result.from_address = clean_header(address).lower()
    result.reply_to = _addresses(msg, "Reply-To")
    result.return_path = clean_header(parseaddr(_first(msg, "Return-Path"))[1]).lower()
    result.to = _addresses(msg, "To")
    result.cc = _addresses(msg, "Cc")
    result.message_id = clean_header(_first(msg, "Message-ID"))
    result.date = clean_header(_first(msg, "Date"))
    result.authentication_results = _header_list(msg, "Authentication-Results")
    result.received_spf = _header_list(msg, "Received-SPF")
    result.received = _header_list(msg, "Received")

    text_parts: list[str] = []
    html_parts: list[str] = []
    links: list[Link] = []
    budget = MAX_TEXT_CHARS
    parts_seen = 0
    stack: list[tuple[EmailMessage, int]] = [(msg, 0)]

    while stack:
        part, depth = stack.pop()
        parts_seen += 1
        if parts_seen > MAX_PARTS:
            result.defects.append("too_many_parts")
            result.truncated = True
            break
        result.defects.extend(type(d).__name__ for d in getattr(part, "defects", []))

        if part.is_multipart():
            if depth >= MAX_DEPTH:
                result.defects.append("nesting_too_deep")
                result.truncated = True
                continue
            children = part.get_payload()
            if isinstance(children, list):
                # Reversed so the stack pops children in their original order.
                stack.extend((child, depth + 1) for child in reversed(children))
            continue

        content_type = part.get_content_type()
        try:
            filename = part.get_filename() or ""
            disposition = part.get_content_disposition() or ""
        except Exception:  # noqa: BLE001
            filename, disposition = "", ""
            result.defects.append("bad_disposition")

        if disposition == "attachment" or filename or not content_type.startswith("text/"):
            try:
                size = len(part.get_payload(decode=True) or b"")
            except Exception:  # noqa: BLE001
                size = 0
                result.defects.append("undecodable_part")
            result.attachments.append(
                Attachment(
                    filename=clean_header(filename, 255), content_type=content_type, size=size
                )
            )
            continue

        if budget <= 0:
            result.truncated = True
            continue

        text = _decode_part(part, result)
        if content_type == "text/html":
            extractor = _HTMLExtractor(budget)
            if len(text) > MAX_HTML_SOURCE_CHARS:
                text = text[:MAX_HTML_SOURCE_CHARS]
                result.truncated = True
            try:
                extractor.feed(text)
                extractor.close()
            except Exception:  # noqa: BLE001
                result.defects.append("bad_html")
            extracted = extractor.text()
            html_parts.append(extracted)
            links.extend(extractor.links)
            budget -= len(extracted)
            result.truncated |= extractor.truncated
        else:
            piece = text[:budget]
            result.truncated |= len(piece) < len(text)
            text_parts.append(piece)
            budget -= len(piece)

    result.text_body = "\n".join(text_parts).strip()
    result.html_text = "\n".join(html_parts).strip()

    # Bare URLs written in body text (common in plain-text and SMS-style phishing).
    # A URL that only appears as an anchor's *visible text* is not a link target.
    known = {link.href for link in links}
    anchor_texts = [link.text for link in links if link.source == "html" and link.text]
    for url in extract_urls(result.body):
        if len(links) >= MAX_LINKS:
            result.truncated = True
            break
        if any(url in text for text in anchor_texts):
            continue
        if url not in known:
            known.add(url)
            links.append(Link(href=clean_header(url, MAX_URL_CHARS), text="", source="text"))
    result.links = links[:MAX_LINKS]
    result.defects = sorted(set(result.defects))
    return result


def parse_email_file(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParsedEmail:
    """Read and parse an ``.eml`` file, refusing oversized files before reading them."""
    path = Path(path)
    if path.stat().st_size > max_bytes:
        raise EmailTooLargeError(f"email exceeds {max_bytes} bytes")
    with path.open("rb") as handle:
        raw = handle.read(max_bytes + 1)  # bounded read even if the file grew meanwhile
    return parse_email(raw, max_bytes=max_bytes)
