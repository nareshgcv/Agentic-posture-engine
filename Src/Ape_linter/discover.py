"""
File discovery module for identifying agent configurations, prompts, and source code files.
Skips test, fixture, and example directories by default to eliminate false positives in test suites.
"""
import os
from typing import List, Set

DEFAULT_IGNORE_DIRS: Set[str] = {
    "tests",
    "test",
    "fixtures",
    "examples",
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
}

DEFAULT_IGNORE_FILES: Set[str] = {
    ".env.example",
    "sample.env",
}


def discover_files(root_dir: str = ".") -> List[str]:
    """Walks directory tree and returns relevant agent, config, and source files while pruning test paths."""
    discovered = []
    for root, dirs, files in os.walk(root_dir):
        # Prune ignored directories in-place to prevent walking into test or build suites
        dirs[:] = [
            d
            for d in dirs
            if d.lower() not in DEFAULT_IGNORE_DIRS and not d.startswith(".")
        ]

        for file in files:
            if file.lower() in DEFAULT_IGNORE_FILES:
                continue

            rel_path = os.path.relpath(os.path.join(root, file), root_dir)
            ext = os.path.splitext(file)[1].lower()

            # Include structured configs, prompts/instructions, and source code files
            if (
                ext
                in {
                    ".yaml",
                    ".yml",
                    ".json",
                    ".prompt",
                    ".rules",
                    ".py",
                    ".js",
                    ".ts",
                    ".jsx",
                    ".tsx",
                }
                or file.startswith(".")
            ):
                discovered.append(rel_path)

    return discovered

