# Releasing opendevops

Releases are immutable and tag-driven. A single `vX.Y.Z` tag produces:

- a universal Python wheel containing the compiled TypeScript dashboard and `opendevops init`
  workspace templates;
- a Python source distribution;
- a source-free Compose deployment bundle pinned to the release image;
- `linux/amd64` and `linux/arm64` images in GitHub Container Registry;
- SHA-256 checksums, build provenance, an SBOM, and a GitHub Release.

## Versioning

The only application version source is `src/opendevops/__init__.py`. Hatch reads that value through
`tool.hatch.version`; the release workflow rejects a tag that does not match it.

Use Semantic Versioning while the public interfaces stabilize:

```sh
uvx --from hatch hatch version patch
uvx --from hatch hatch version minor
uvx --from hatch hatch version major
```

Pre-releases use PEP 440 versions such as `0.2.0rc1` and matching tags such as `v0.2.0rc1`.
Published versions and container tags are never replaced.

## Release checklist

1. Update `CHANGELOG.md` and bump the version.
2. Run the complete release gate:

   ```sh
   npm ci
   npm run frontend:check
   npm run frontend:build
   uv sync --all-extras
   uv run ruff check .
   uv run mypy src ops
   uv run pytest
   uv lock --check
   uv build
   uvx twine check dist/*
   ```

3. Commit the release change to `main`, then create and push an annotated or signed tag:

   ```sh
   git tag -s v0.2.0
   git push origin main v0.2.0
   ```

4. Follow the `Release` workflow until all required jobs complete. The workflow creates the GitHub
   Release only after the Python artifacts and multi-architecture image succeed.
5. Verify the release:

   ```sh
   gh attestation verify opendevops-0.2.0-py3-none-any.whl \
     --repo skundu42/opendevops
   sha256sum -c SHA256SUMS
   docker buildx imagetools inspect ghcr.io/skundu42/opendevops:0.2.0
   ```

If a release job fails, fix the release workflow or source and publish a new version. Do not move
an already published tag or overwrite a PyPI version.

## One-time PyPI trusted-publisher setup

PyPI publication is intentionally disabled until the repository owner completes its external
trust setup. In PyPI, create a pending trusted publisher with:

- owner: `skundu42`
- repository: `opendevops`
- workflow: `release.yml`
- environment: `pypi`
- project: `opendevops`

Then create or review the GitHub `pypi` environment and set the repository Actions variable
`PYPI_PUBLISH_ENABLED=true`. The workflow uses GitHub OIDC and never stores a long-lived PyPI API
token. For the first enabled release, confirm `https://pypi.org/project/opendevops/` is still
available before pushing the tag.

## Supported installation paths

Until PyPI trusted publishing is enabled, install the wheel directly from a GitHub Release:

```sh
uv tool install \
  'opendevops[checkpoint,ssh] @ https://github.com/skundu42/opendevops/releases/download/v0.1.0/opendevops-0.1.0-py3-none-any.whl'
```

After PyPI is enabled, the shorter equivalent is:

```sh
uv tool install "opendevops[checkpoint,ssh]==0.2.0"
```
