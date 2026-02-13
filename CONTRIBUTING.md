# Contributing to ZIA Ansible Collection

Thank you for your interest in contributing. This document covers development setup and testing.

## Development Setup

The collection must be placed at `<path>/ansible_collections/zscaler/ziacloud` (see Makefile for details).

1. Install dependencies with Poetry:

   ```bash
   poetry install
   ```

2. (Optional) Install Ansible for integration/sanity tests:

   ```bash
   poetry run pip install 'ansible-core>=2.15,<2.17'
   ```

## Running Unit Tests

All commands below are run from the **collection root** (the directory containing `pyproject.toml`).

### Run tests

```bash
poetry run pytest tests/unit/ -v
```

### Run tests with coverage

```bash
poetry run pytest tests/unit/ \
  --cov=plugins \
  --cov-branch \
  --cov-report=term-missing \
  --cov-report=xml:coverage.xml \
  --cov-report=html:htmlcov
```

### Coverage summary

- **Line coverage** – percentage of statements executed
- **Branch coverage** – percentage of decision branches executed
- **coverage.xml** – machine-readable report (used by Codecov)
- **htmlcov/** – HTML report for browsing (open `htmlcov/index.html`)

### Check coverage thresholds

After running tests with coverage, verify thresholds:

```bash
poetry run python scripts/check_coverage.py --line-min 70 --branch-min 55
```

CI enforces:
- Line coverage ≥ 70%
- Branch coverage ≥ 48% (current baseline; goal 55%)

## CI Workflow

The [Unit Tests workflow](.github/workflows/unit-tests.yml) runs on push/PR to `master`, schedule, and manual dispatch. It:

1. Runs pytest with `--cov-branch`
2. Fails if line coverage < 70% or branch coverage < 55%
3. Uploads `coverage.xml` to Codecov
4. Publishes test results

## Code Style

- Format code with Black: `make format` or `black .`
- Lint with ansible-lint and project-specific rules
