# Release a version to PyPI

A tag `vX.Y.Z` runs `.github/workflows/release.yml`: it checks the tag matches the version in `pyproject.toml`, builds the wheel and the sdist, publishes them to TestPyPI, then to PyPI (ADR-0008). Publishing uses PyPI's trusted publishing: PyPI trusts this repository's workflow, so no token is stored in GitHub or anywhere else.

Before any tag, CI's "The wheel installs and works, with each extra" job has already installed the wheel in a fresh environment, with no extra and with each one, and run the README's integration snippet against it.

## Once: the trusted publishers

On [pypi.org](https://pypi.org/manage/account/publishing/) and [test.pypi.org](https://test.pypi.org/manage/account/publishing/), each with its own account, add a **pending publisher** (the project does not exist yet; the first publish creates it):

| Field | PyPI | TestPyPI |
| --- | --- | --- |
| PyPI project name | `fastapi-sentinel` | `fastapi-sentinel` |
| Owner | `Alesso2805` | `Alesso2805` |
| Repository name | `sentinelapi` | `sentinelapi` |
| Workflow name | `release.yml` | `release.yml` |
| Environment name | `pypi` | `testpypi` |

The GitHub environments `pypi` and `testpypi` exist already. To make every release wait for a click, add yourself as a required reviewer of `pypi` (Settings → Environments).

The distribution is `fastapi-sentinel`; the package it installs is `sentinelapi`. PyPI refused a pending publisher for `sentinelapi` as too similar to the existing `sentinel-api`: it compares names without separators and with confusable characters folded, so check that form too before choosing a name. A pending publisher does not reserve the name; the first publish does.

## Each release

1. On a branch: `uv version X.Y.Z` and `make openapi` (the demo's document carries the version), then move `CHANGELOG.md`'s Unreleased section under `## [X.Y.Z] - <date>` and add its comparison link at the bottom. Open the PR and merge it once CI is green.
2. Tag the merge commit and push the tag:

   ```bash
   git switch main && git pull
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

3. Follow the "Release" run in the Actions tab. If TestPyPI fails, PyPI is never tried.
4. Check it as a user would, in a fresh environment:

   ```bash
   uv venv /tmp/check && uv pip install --python /tmp/check "fastapi-sentinel[sqlite]==X.Y.Z"
   ```

A version cannot be published twice: to fix a broken release, release `X.Y.Z+1`.
