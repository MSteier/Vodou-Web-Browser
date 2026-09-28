# Working in this repo

## Git workflow: PRs are required on `master` and `linux-support`

Both branches have GitHub branch protection that:

- Requires a pull request to merge (0 approvals needed, so a solo PR from
  yourself can still be merged once checks pass).
- Requires the `audit` status check (`.github/workflows/dependency-audit.yml`,
  runs `pip-audit` against `requirements.txt`) to pass.
- Is enforced for admins too — there is no bypass.

**A plain `git push origin master` (or `linux-support`) will be rejected.**
That's expected, not a bug and not a broken remote/auth. Don't try to work
around it (no force-push, no disabling the hook, no re-adding a bypass).

The actual workflow is:

```bash
git checkout -b some-branch-name
git commit -m "..."
git push -u origin some-branch-name
gh pr create --base master --fill   # or --base linux-support
# wait ~30s for the "audit" check to go green, then:
gh pr merge --squash   # or --merge, whichever matches existing history
```

This was set up 2026-09-25 specifically so a dependency CVE can't land on
either branch unnoticed — see git log around that date for the discussion if
the reasoning here ever needs re-deriving.

## Docker Hub release checklist

`docker/HUB_README.md` is the source of truth for the Docker Hub page (changelog
and pinned version), but **Docker Hub does not read it automatically**: this repo
isn't linked via Docker Hub's Autobuild, so `docker push` never touches the
repository description. Forgetting to publish it is how the page went stale for
several releases (still showing `1.50.1` as of 2026-09-25, and 1.54.8 on
2026-09-28).

### Version numbers: app releases vs. Docker-only rebuilds

`APP_VERSION` in `about.py` is **the app's version**, and every installed copy
polls it (`UpdateChecker` reads `about.py` from GitHub) to decide whether to
show "update available". So bump it **only when Vodou itself changes**.

- **App release** (any change to what the browser does): bump `APP_VERSION`,
  tag the image `X.Y.Z` + `latest`, publish the Windows release.
- **Docker-only rebuild** (Dockerfile, base image, OS packages, a fresh
  no-cache rebuild for CVE fixes): **leave `APP_VERSION` alone**. Tag the image
  `<APP_VERSION>-rN` (first rebuild `-r1`, then `-r2`, ...) + `latest`, add the
  changelog entry and pinned tag under that name in `docker/HUB_README.md`, and
  skip the Windows release. Bumping `APP_VERSION` for 1.54.7 and 1.54.9 (both
  Docker-only) told every desktop user an update existed when none did.

`about._version_tuple` reads only each segment's leading number, so
`1.54.10-r1` compares equal to `1.54.10` (tested in
`tests/test_update_state.py`). Never put a `-rN` suffix in `APP_VERSION`.

Every version bump that gets pushed to Docker Hub needs all three:

1. Bump `APP_VERSION` in `about.py` (app releases only; see above) and add the
   changelog entry + new pinned tag to `docker/HUB_README.md`.
2. Build and `docker push` the new tags.
3. **Run `python docker/sync_hub_readme.py`** to publish `HUB_README.md` as the
   Docker Hub description. It uses the Docker Hub login already stored by
   `docker login` / Docker Desktop (OS credential store), holds it in memory
   only, and verifies the live page afterwards. `--check` just reports whether
   the page is current.

Deliberately **not** a GitHub Action: that would need a Docker Hub access token
stored as a repo secret, which the owner prefers not to create. So step 3 runs
from a machine logged in to Docker Hub as `msteier`; never put a token or
password in the repo, a workflow, or the script.
