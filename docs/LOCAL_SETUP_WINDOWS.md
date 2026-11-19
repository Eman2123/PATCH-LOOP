# Local Setup on Windows

This guide covers the local development workflow for PATCH-LOOP on Windows using PowerShell.

## Prerequisites

- Python 3.11 or a version supported by the backend dependencies
- Node.js and npm
- Git

Check that the required command-line tools are available:

```powershell
py --version
node --version
npm --version
git --version
```

Docker and a Vultr API key are not required for the backend unit tests.

If the Windows `py` launcher is unavailable, replace `py` with `python` in the commands below.

## Backend

From the repository root:

```powershell
cd backend
py -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m pytest -q
```

If PowerShell blocks virtual-environment activation, allow scripts for the current process only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\\.venv\\Scripts\\Activate.ps1
```

## Frontend

Open a second PowerShell terminal from the repository root:

```powershell
cd frontend
npm ci
npm test
npm run build
```

## Configuration and secrets

Start from `.env.example` when configuring the backend. Keep real credentials in your local `.env` file or environment variables. Never commit API keys, admin tokens, or other secrets.

For live model calls, set the inference key only in the terminal session that needs it:

```powershell
$env:VULTR_API_KEY = "your-key"
```

Do not paste real credentials into source files, issue comments, or screenshots.

## Notes

- Run backend tests from the `backend` directory.
- Run frontend commands from the `frontend` directory.
- The local test workflow does not require a running Docker daemon unless you are exercising Docker-backed sandbox functionality.
- See [DEPLOY.md](DEPLOY.md) for VM deployment instructions.
