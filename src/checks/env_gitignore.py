"""Check if .env is properly gitignored."""

import os
from pathlib import Path


def check_env_gitignored(root: str = ".") -> dict:
    """Verify that .env files are excluded from version control.

    Returns:
        dict with 'safe' (bool), 'reason' (str), and 'files' (list of found .env files)
    """
    results = {"safe": True, "reason": "", "files": []}

    gitignore_path = Path(root) / ".gitignore"
    if not gitignore_path.exists():
        results["safe"] = False
        results["reason"] = "No .gitignore file found"
        return results

    gitignore_content = gitignore_path.read_text()
    has_env_rule = any(
        line.strip() in (".env", ".env*", ".env.local", ".env.*")
        for line in gitignore_content.splitlines()
        if line.strip() and not line.startswith("#")
    )

    if not has_env_rule:
        results["safe"] = False
        results["reason"] = ".gitignore does not exclude .env files"
        return results

    for pattern in [".env", ".env.local", ".env.production"]:
        p = Path(root) / pattern
        if p.exists():
            results["files"].append(str(p))

    if results["files"]:
        results["safe"] = False
        results["reason"] = f".env file(s) exist but should be tracked: {', '.join(results['files'])}"

    return results
