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

`docker/HUB_README.md` is the source of truth for the changelog and pinned
version, but **Docker Hub does not read it automatically** — this repo isn't
linked via Docker Hub's Autobuild, so `docker push` never touches the
repository description. Updating the file in git and forgetting this step is
how the Docker Hub page went stale for several releases (still showing
`1.50.1` pinned and an old changelog entry as of 2026-09-25, despite the git
file being current through 1.54.2).

Every version bump that gets pushed to Docker Hub needs BOTH:

1. Bump `APP_VERSION` in `about.py` and add the changelog entry + new pinned
   tag to `docker/HUB_README.md` (as usual).
2. Build and `docker push` the new tags.
3. **Manually paste the full contents of `docker/HUB_README.md` into Docker
   Hub's "Full Description" field** (msteier/vodou repo → General tab → edit
   the description). There is no API-free way to skip this, and skipping it
   is not a bug — it's this exact known gap.
