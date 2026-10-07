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
import http.client
import shutil
import ssl

# Only fixed git commands are run, with an argument list and no shell.
import subprocess  # nosec B404
import sys
import time
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
    "CEAS_08.csv": (
        f"{_EMAIL_MIRROR}/CEAS_08.csv",
        "22375e7d5f5a8229dbe987914ee9b3705656c590038662a7df6054629b376074",
    ),
    "Ling.csv": (
        f"{_EMAIL_MIRROR}/Ling.csv",
        "c133792260f18b251e9377b9cb31bef226322af6dc0d79841f61c67489929eca",
    ),
    "sms.tsv": (
        "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv",
        "7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d",
    ),
    # Mishra & Soni (2022) SMS phishing dataset (Mendeley, CC BY 4.0): ham/smishing/spam.
    "sms_mendeley_5971.csv": (
        "https://raw.githubusercontent.com/nmbenton/INFO-4360-Project/main/Dataset_5971.csv",
        "649844f1c62a6b27e145eaf17a65f7010c56c390e11a794ea8329993a05ba71e",
    ),
}


# Git sources are pinned to a full commit hash: git verifies every object against it,
# so the checked-out files are exactly that snapshot.
GIT_SOURCES: dict[str, tuple[str, str, str]] = {
    # name: (https repo url, commit, sub-directory to check out)
    "phishing_pot": (
        "https://github.com/rf-peixoto/phishing_pot.git",
        "89e2bc05d159555389782f2fbe8d916588cd49cd",
        "email/",
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


class DownloadError(ValueError):
    """A download was refused (size, hash or transfer problem)."""


def _fetch_once(name: str, url: str, tmp: Path) -> int:
    request = urllib.request.Request(  # noqa: S310 - pinned https URL, https-only opener
        url, headers={"User-Agent": "phishguard-dataset-fetch", "Accept-Encoding": "identity"}
    )
    total = 0
    with https_only_opener().open(request, timeout=TIMEOUT) as response, tmp.open("wb") as out:
        declared = response.headers.get("Content-Length")
        while chunk := response.read(1 << 20):
            total += len(chunk)
            if total > MAX_BYTES:
                raise DownloadError(f"{name}: exceeds {MAX_BYTES} bytes, aborting")
            out.write(chunk)
    if declared is not None and declared.isdigit() and int(declared) != total:
        raise DownloadError(f"{name}: truncated transfer ({total} of {declared} bytes)")
    return total


def download(name: str, url: str, expected: str | None, attempts: int = 3) -> Path:
    """Download one pinned file. Transient corruption is retried; a file is only
    accepted if its SHA-256 matches the pin (never on "best effort")."""
    if not url.startswith("https://"):
        raise ValueError(f"{name}: refusing non-HTTPS URL")
    target = RAW_DIR / name
    if target.exists() and expected and sha256_file(target) == expected:
        print(f"[ok]   {name} already present and verified")
        return target

    tmp = target.with_suffix(target.suffix + ".part")
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            total = _fetch_once(name, url, tmp)
            actual = sha256_file(tmp)
            if expected is None:
                print(f"[pin]  {name}: sha256={actual} (pin this value in DATASETS)")
            elif actual != expected:
                raise DownloadError(f"{name}: SHA-256 mismatch (expected {expected}, got {actual})")
            tmp.replace(target)
            print(f"[done] {name}: {total / 1e6:.1f} MB")
            return target
        # URLError/timeouts are OSErrors; IncompleteRead is an http.client.HTTPException.
        except (DownloadError, OSError, http.client.HTTPException) as exc:
            tmp.unlink(missing_ok=True)
            last_error = str(exc)
            if attempt < attempts:
                print(f"[retry] {name}: attempt {attempt} failed ({exc}); retrying")
                time.sleep(2 * attempt)
    raise DownloadError(f"{last_error} - gave up after {attempts} attempts")


def _git(*args: str, cwd: Path | None = None) -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required for git-hosted datasets")
    # Fixed argv, no shell; transport restricted to https via protocol.allow.
    result = subprocess.run(  # noqa: S603  # nosec B603
        [git, "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", *args],
        cwd=cwd, check=True, capture_output=True, text=True, timeout=1800,
    )
    return result.stdout.strip()


def fetch_git(name: str, url: str, commit: str, subdir: str) -> Path:
    """Sparse, blob-less checkout of one folder at an exact commit (HTTPS only)."""
    if not url.startswith("https://") or len(commit) != 40:
        raise ValueError(f"{name}: need an https URL and a full 40-char commit hash")
    target = RAW_DIR / name
    if target.exists():
        if _git("rev-parse", "HEAD", cwd=target) == commit:
            print(f"[ok]   {name} already present at pinned commit {commit[:12]}")
            return target
        shutil.rmtree(target)
    _git("init", "-q", str(target))
    _git("remote", "add", "origin", url, cwd=target)
    _git("sparse-checkout", "set", "--no-cone", subdir, cwd=target)
    _git("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit, cwd=target)
    _git("checkout", "-q", commit, cwd=target)
    if _git("rev-parse", "HEAD", cwd=target) != commit:
        shutil.rmtree(target)
        raise ValueError(f"{name}: checked-out commit does not match the pin")
    print(f"[done] {name} at pinned commit {commit[:12]}")
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
    for name, (url, commit, subdir) in GIT_SOURCES.items():
        try:
            fetch_git(name, url, commit, subdir)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"[fail] {name}: {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
