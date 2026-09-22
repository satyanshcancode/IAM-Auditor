# IAM Access Auditor & Permission Analyzer v2.0

A Python toolkit for reviewing AWS IAM users, groups, roles, policies, and effective permissions. It includes a **FastAPI REST API**, a **Typer CLI**, **JSON/CSV/SARIF export**, and **Docker** support.

## Architecture

There are two layers on purpose; they share one implementation of IAM logic:

- `aws/` is the shared IAM operations layer (list, analyze, simulate, search, compare, report). The legacy interactive `main.py` still prints from this package.
- `iam_audit/` is the v2 product surface: Pydantic models, Typer CLI, FastAPI, and exporters. It wraps `aws/` instead of re-implementing comparison, search, or simulation.

Do not add a second copy of permission-diff or simulation logic in `iam_audit/core/engine.py`.

## What's New in v2.0

- **FastAPI REST API** — Query IAM data, run audits, and check permissions over HTTP
- **Typer CLI** — Command-line interface with Rich tables
- **Export formats** — JSON, CSV, and SARIF
- **Structured logging** — Configurable logging in the v2 CLI/API
- **Pydantic models** — Validated report and analysis objects
- **Docker & Docker Compose** — API service plus a CLI profile
- **CI/CD pipeline** — GitHub Actions with linting, type checking, tests, and a Docker build
- **Optional API key** — Set `IAM_AUDIT_API_KEY` to require `X-API-Key` on `/api/v1/*`

## Quick Start

### Prerequisites

- Python 3.10+
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- IAM read permissions for the APIs listed below

### Installation

```bash
pip install -r requirements.txt
pip install -e .
```

Or install with extras:

```bash
pip install -e ".[all]"
```

## Usage

### 1. Modern CLI (Typer)

```bash
# Run a full audit and print summary
iam-audit audit

# Export audit to JSON ( --output is required for json/csv/sarif )
iam-audit audit --format json --output report.json

# Export audit to SARIF for security scanners
iam-audit audit --format sarif --output findings.sarif

# List IAM inventory
iam-audit inventory

# Analyze a user's permissions
iam-audit permissions alice --output alice.json

# Check a specific permission
iam-audit check alice s3:GetObject

# Search users by permission
iam-audit search s3:PutObject

# Compare two users
iam-audit compare alice bob
```

`python -m iam_audit.cli.main` works the same way if the console script is not on `PATH`.

### 2. REST API (FastAPI)

Protect inventory and audit endpoints in any non-local environment:

```bash
export IAM_AUDIT_API_KEY="replace-me"
uvicorn iam_audit.api.main:app --host 0.0.0.0 --port 8000
```

If `IAM_AUDIT_API_KEY` is unset, `/api/v1/*` stays open (local development only). `/health` and `/` are always public.

```bash
# Docker Compose
docker-compose up iam-audit-api
```

API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/inventory` | List users, groups, roles |
| GET | `/api/v1/audit` | Run full security audit |
| GET | `/api/v1/users/{username}/permissions` | User permission analysis |
| POST | `/api/v1/permissions/check` | Check specific permission |
| POST | `/api/v1/permissions/search` | Search users by permission |
| GET | `/api/v1/users/compare?user1=alice&user2=bob` | Compare two users |

Interactive docs: `http://localhost:8000/docs`.

### 3. Docker

```bash
# Build and run API
docker build -t iam-audit .
docker run -p 8000:8000 -v ~/.aws:/root/.aws:ro iam-audit

# Or use Docker Compose
docker-compose up

# Run CLI in container (installs the iam-audit entry point in the image)
docker-compose --profile cli up iam-audit-cli
```

### 4. Legacy CLI (still works)

```bash
python main.py
```

## AWS Permissions Needed

- `iam:GetUser`, `iam:ListUsers`, `iam:ListGroups`, `iam:ListRoles`
- `iam:ListGroupsForUser`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`
- `iam:ListAttachedGroupPolicies`, `iam:ListGroupPolicies`
- `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`
- `iam:GetPolicy`, `iam:GetPolicyVersion`
- `iam:GetUserPolicy`, `iam:GetGroupPolicy`
- `iam:SimulatePrincipalPolicy`

## Project Structure

```
.
├── aws/                     # Shared IAM operations (used by legacy CLI and iam_audit)
├── iam_audit/
│   ├── core/
│   │   ├── engine.py        # Structured wrappers around aws/
│   │   ├── models.py        # Pydantic data models
│   │   └── logging.py       # Logging configuration
│   ├── api/
│   │   └── main.py          # FastAPI REST API
│   ├── cli/
│   │   └── main.py          # Typer CLI
│   └── exporters/
│       └── base.py          # JSON, CSV, SARIF exporters
├── tests/                   # Test suite
├── .github/workflows/
│   └── ci.yml               # GitHub Actions CI/CD
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Development

```bash
# Run tests with coverage
pytest --cov=iam_audit --cov=aws --cov-report=html

# Lint
ruff check aws/ iam_audit/ tests/
ruff format aws/ iam_audit/ tests/

# Type check
mypy iam_audit/ aws/
```

## Notes on Accuracy

The user permission inventory includes:

- User-attached managed policies
- User inline policies
- Group-attached managed policies
- Group inline policies
- Explicit deny actions listed separately
- Paginated IAM list results

For a precise AWS decision on a specific permission, use `iam-audit check`, which calls IAM `SimulatePrincipalPolicy`.

The action inventory is a simplified view. IAM statements with `Resource`, `Condition`, or `NotAction` require deeper review because they cannot always be represented as a simple list of allowed actions.

## License

MIT
