# Release workflow recovery

Version-tag pushes run the official SIFT/recovery gate, platform builds, archive
smoke tests, container publication, provenance and signing before creating a
GitHub Release. SIFT conversion uses Python 3.12 and the pinned binary wheel for
`h5py==3.14.0` so runner Python upgrades cannot silently trigger an HDF5 source
build.

If a release workflow fails before publication, fix its automation through a
normal protected PR. Keep the original version tag unchanged. After the repair
merges, retry from the default-branch workflow:

```sh
gh workflow run release.yml --repo Gaussian-id/ChironDB --ref main \
  -f release_tag=v0.1.0-beta.3
```

The retry accepts only an existing version tag whose source is in the default
branch history and whose package version matches. Every release gate remains
enabled. The workflow resolves the tag once and checks out that immutable SHA
for every build. Benchmark reports and image revision labels identify that
source. Each archive includes `RELEASE_SOURCE.json`, recording both the source
tag/SHA and the workflow ref/SHA; the GitHub provenance attestation identifies
the workflow that performed the build. The tag is checked again before GitHub
Release creation. No tag is created or moved by the retry.

Leave `release_tag` empty to retain the existing qualification-only dispatch:
official SIFT/recovery runs on the selected workflow commit without publishing
archives, images or a GitHub Release. Retry publication requires the workflow
on the default branch; candidate branches cannot use that path.

On the first GHCR publication, a package administrator must set the package's
visibility to public in its GitHub package settings. Repository permission
inheritance does not set package visibility; GitHub provides no REST package
visibility update endpoint. The workflow checks an actual anonymous manifest
fetch using an empty Docker credential configuration, with 60 attempts and a
15-second delay between checks. If the package remains private or unavailable,
publication fails closed. Set its
visibility and rerun the failed jobs after correcting access. See
[GitHub's package visibility documentation](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).
