"""Regenerate installer/mocat.ico (the MoCat HomeSOC Windows icon) from app/ui/logo.png.

Used by installer/homesoc.spec (both EXEs) and installer/homesoc.iss (SetupIconFile). Build-time
only: never bundled. Run from the repo root after changing the logo, then commit mocat.ico:

    .venv\\Scripts\\python installer\\make_icon.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
LOGO = ROOT / "app" / "ui" / "logo.png"
ICO = ROOT / "installer" / "mocat.ico"
SIZES: tuple[int, ...] = (16, 24, 32, 48, 64, 128, 256)


def make_icon(src: Path = LOGO, dst: Path = ICO, sizes: tuple[int, ...] = SIZES) -> Path:
    """Write a multi-size .ico of ``src`` (an RGBA PNG) to ``dst``; returns ``dst``."""
    from PIL import Image

    with Image.open(src) as img:
        square = _square(img.convert("RGBA"), Image)
        biggest = max(sizes)
        if square.width < biggest:
            square = square.resize((biggest, biggest), Image.Resampling.LANCZOS)
        dst.parent.mkdir(parents=True, exist_ok=True)
        square.save(dst, format="ICO", sizes=[(s, s) for s in sizes])
    return dst


def _square(img: Any, image_module: Any) -> Any:
    """Centre ``img`` on a transparent square canvas (no stretching)."""
    side = max(img.size)
    if img.width == img.height:
        return img
    canvas = image_module.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.paste(img, ((side - img.width) // 2, (side - img.height) // 2))
    return canvas


if __name__ == "__main__":
    out = make_icon()
    print(f"wrote {out.relative_to(ROOT)} ({', '.join(map(str, SIZES))} px)")
    sys.exit(0)
