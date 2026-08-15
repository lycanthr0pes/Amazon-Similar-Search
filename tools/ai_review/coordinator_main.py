"""Pinned coordinator-image entrypoint.

The external root-owned launcher verifies the image digest and read-only asset mounts before this
module starts.  Isolated Python intentionally omits the working directory, so the trusted image
entrypoint adds only its fixed application root before importing the coordinator CLI.
"""

from __future__ import annotations

import sys
from pathlib import Path


APPLICATION_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(APPLICATION_ROOT))

from tools.ai_review.cli import main  # noqa: E402


raise SystemExit(main())
