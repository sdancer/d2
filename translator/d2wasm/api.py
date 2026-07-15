from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class ApiSpec:
    library: str
    name: str
    arg_bytes: int
    convention: str
    no_return: bool = False

    @property
    def key(self) -> str:
        return f"{self.library.lower()}!{self.name}"


def load_api_specs(path: Path) -> dict[str, ApiSpec]:
    raw = json.loads(path.read_text())
    result = {}
    for item in raw["apis"]:
        spec = ApiSpec(
            library=item["library"],
            name=item["name"],
            arg_bytes=int(item["arg_bytes"]),
            convention=item.get("convention", "stdcall"),
            no_return=bool(item.get("no_return", False)),
        )
        if spec.convention not in ("stdcall", "cdecl"):
            raise ValueError(f"unsupported calling convention for {spec.key}: {spec.convention}")
        result[spec.key] = spec
    return result

