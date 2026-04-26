# Cursor + Phantom Secrets Tutorial

This guide walks through setting up Phantom Secrets with Cursor IDE for seamless secret management.

## Prerequisites

- [Cursor](https://cursor.sh) installed
- Phantom Secrets CLI installed (`npm install -g phantom-secrets`)
- A Phantom account

## Step 1: Configure Phantom in Cursor

1. Open Cursor Settings (`Ctrl+,`)
2. Navigate to Extensions > Phantom Secrets
3. Enter your API key from the Phantom dashboard

## Step 2: Initialize Project

```bash
cd your-project
phantom init
```

This creates `.phantom/config.json` in your project root.

## Step 3: Use Secrets in Code

Phantom automatically injects secrets at runtime:

```python
import os
db_password = os.getenv("DB_PASSWORD")  # Auto-filled by Phantom
```

## Step 4: Run with Phantom

```bash
phantom run -- python app.py
```

Or configure Cursor's terminal to always wrap commands with `phantom run`.

## Tips

- Use `phantom list` to see all available secrets
- Secrets are never stored in plaintext on disk
- Share configs (not secrets) with your team via `.phantom/config.json`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Secrets not loading | Run `phantom auth login` |
| Permission denied | Check `.env` file permissions |
| Cursor not detecting | Restart Cursor after install |

---

For more details, see the [main README](../README.md).