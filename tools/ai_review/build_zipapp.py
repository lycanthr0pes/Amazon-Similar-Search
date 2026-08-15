from __future__ import annotations

import argparse
import os
import zipfile
from pathlib import Path

from tools.ai_review.path_safety import resolve_safe_input
from tools.ai_review.path_safety import resolve_safe_output
from tools.ai_review.hashing import sha256_file


ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIPAPP_MAIN = b"from tools.ai_review.cli import main\n\nraise SystemExit(main())\n"


def _archive_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def build_trusted_zipapp(source_root: Path, output: Path) -> str:
    """Build a reproducible archive; approval must happen outside this builder."""

    root = source_root.resolve(strict=True)
    package_root = root / "tools" / "ai_review"
    source_files = [root / "tools" / "__init__.py", *sorted(package_root.glob("*.py"))]
    safe_sources = [resolve_safe_input(path) for path in source_files]
    safe_output = resolve_safe_output(output)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(safe_output.parent, directory_flags)
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        output_fd = os.open(safe_output.name, flags, 0o600, dir_fd=directory_fd)
        created = True
        with os.fdopen(output_fd, "w+b") as handle:
            with zipfile.ZipFile(handle, mode="w") as archive:
                archive.writestr(_archive_info("__main__.py"), ZIPAPP_MAIN)
                for path in safe_sources:
                    relative = path.relative_to(root).as_posix()
                    archive.writestr(_archive_info(relative), path.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if created:
            try:
                os.unlink(safe_output.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(directory_fd)

    return sha256_file(safe_output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the deterministic AI review zipapp")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    print(build_trusted_zipapp(args.source_root, args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
