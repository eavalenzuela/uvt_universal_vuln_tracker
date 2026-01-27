# Testing Guide

This project uses `pytest` for automated tests. The suite exercises the core API endpoints to ensure solid coverage of the Flask backend, including catalogs (controls, attack vectors, terminal impacts) and plugin runs.

## Setup

1. Create and activate a virtual environment.
2. Install dependencies (includes testing tools):
   ```bash
   pip install -r requirements.txt
   ```

## Running the tests

Run the full suite with coverage:
```bash
pytest --cov=backend --cov-report=term-missing
```

The command will:
- Initialize an in-memory SQLite database for each test.
- Hit key API endpoints with valid and invalid payloads.
- Produce a coverage report showing line-by-line execution.

## Notes

- Public registration is enabled during tests to bootstrap the initial admin user.
- Tokens are generated via the existing JWT helpers to match production authentication.
- If you add new endpoints, include matching tests so coverage stays at 100% for the API layer.
