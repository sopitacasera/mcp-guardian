from __future__ import annotations

import json
from pathlib import Path

from mcp_guardian.models import ScanResult


class JsonReporter:
    def write(self, result: ScanResult, path: Path) -> None:
        path.write_text(
            json.dumps(result.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )
