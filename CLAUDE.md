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
