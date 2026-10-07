"""One command to get a working, verified model: download data if needed, then train
only when the model is missing or fails its integrity check.

Run:  python scripts/bootstrap.py           (idempotent, safe to re-run)
      python scripts/bootstrap.py --force   (always retrain)
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phishguard import text_model  # noqa: E402


def _download() -> int:
    path = ROOT / "scripts" / "download_data.py"
    spec = importlib.util.spec_from_file_location("download_data", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main()


def model_is_valid(name: str = "email_model") -> bool:
    try:
        text_model.load_model(name)
    except text_model.ModelIntegrityError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="retrain even if a valid model exists")
    args = parser.parse_args(argv)

    if not args.force and model_is_valid():
        print("[ok] email_model present and matches models/manifest.json - nothing to do")
        return 0
    if _download() != 0:
        print("[fail] dataset download failed - see messages above", file=sys.stderr)
        return 1
    return text_model.main(["train-email"])


if __name__ == "__main__":
    raise SystemExit(main())
