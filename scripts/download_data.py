"""Download the public training datasets into data/raw/ (gitignored).

Security measures:
* URLs are pinned in this file. Nothing is downloaded from user input.
* HTTPS only, enforced structurally: the opener has *no* http:, file: or ftp:
  handler, so even a malicious redirect can't downgrade or read local files.
  Also a timeout and a hard size cap per file.
* Each file is checked against a pinned SHA-256 so the exact bytes the model was
  trained on are reproducible, and a changed or tampered mirror is detected.
  On the very first download (hash ``None``) the hash is printed so you can pin it.
* Files are written to a temporary name and renamed only after verification, so
  a partial or rejected download never looks like a valid dataset.
* Raw data is never printed. Only file names, sizes and hashes are logged.

Run:  python scripts/download_data.py
"""

from __future__ import annotations

import hashlib
import ssl
import sys
import urllib.request
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
MAX_BYTES = 120 * 1024 * 1024
TIMEOUT = 60

# The original hosts (Kaggle, UCI) are not reachable from every environment, so
# these are public GitHub mirrors of the same files. See data/README.md for provenance.
_EMAIL_MIRROR = "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main"
DATASETS: dict[str, tuple[str, str | None]] = {
    # name: (url, sha256)
    "Nazario.csv": (
        f"{_EMAIL_MIRROR}/Nazario.csv",
        "b8fbc4158fbdfaff1ed98584c43d72e283c6352d7ade4d457d34c1d79488d184",
    ),
    "Nigerian_Fraud.csv": (
        f"{_EMAIL_MIRROR}/Nigerian_Fraud.csv",
        "f5d6930763cae6feeae6484131c79655a7440abbb97d6f51eab757aea4e6ab4b",
    ),
    "Enron.csv": (
        f"{_EMAIL_MIRROR}/Enron.csv",
        "99933d3233510cf5dc2ee7768ddc609425cb8002bf5d7691d9a7157ffa5fd318",
    ),
    "SpamAssasin.csv": (
        f"{_EMAIL_MIRROR}/SpamAssasin.csv",
        "3bfe8f8abff89f69a98456be50413c2fcb20a476141116dd84ee1507b980c00e",
    ),
    "sms.tsv": (
        "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv",
        "7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d",
    ),
}


def https_only_opener() -> urllib.request.OpenerDirector:
    """An opener that can only speak HTTPS (through the environment's proxy)."""
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),  # honours HTTPS_PROXY
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        urllib.request.HTTPRedirectHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.UnknownHandler(),  # any other scheme -> explicit "unknown url type"
    ):
        opener.add_handler(handler)
    return opener


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(name: str, url: str, expected: str | None) -> Path:
    if not url.startswith("https://"):
        raise ValueError(f"{name}: refusing non-HTTPS URL")
    target = RAW_DIR / name
    if target.exists() and expected and sha256_file(target) == expected:
        print(f"[ok]   {name} already present and verified")
        return target

    tmp = target.with_suffix(target.suffix + ".part")
    request = urllib.request.Request(  # noqa: S310 - pinned https URL, https-only opener
        url, headers={"User-Agent": "phishguard-dataset-fetch"}
    )
    total = 0
    opener = https_only_opener()
    with opener.open(request, timeout=TIMEOUT) as response, tmp.open("wb") as out:
        while chunk := response.read(1 << 20):
            total += len(chunk)
            if total > MAX_BYTES:
                out.close()
                tmp.unlink(missing_ok=True)
                raise ValueError(f"{name}: exceeds {MAX_BYTES} bytes, aborting")
            out.write(chunk)

    actual = sha256_file(tmp)
    if expected is None:
        print(f"[pin]  {name}: sha256={actual} (pin this value in DATASETS)")
    elif actual != expected:
        tmp.unlink(missing_ok=True)
        raise ValueError(f"{name}: SHA-256 mismatch (expected {expected}, got {actual})")
    tmp.replace(target)
    print(f"[done] {name}: {total / 1e6:.1f} MB")
    return target


def main() -> int:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    failed = 0
    for name, (url, expected) in DATASETS.items():
        try:
            download(name, url, expected)
        except Exception as exc:  # noqa: BLE001 - report and continue with the others
            failed += 1
            print(f"[fail] {name}: {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
