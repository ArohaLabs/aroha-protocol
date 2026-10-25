<!-- Internal note — this file exists only in the private monorepo and is
     never pushed to the public spec repo. -->

# Published: github.com/ArohaLabs/aroha-spec

This directory is the staging copy of the **public** spec repo. The public repo
is the canonical face; this directory is where edits originate.

## The three copies

The spec exists in three places, and `sync.sh` is what keeps them equal:

| Copy | Role |
|------|------|
| `spec-public/spec/` | **Source of truth.** Edit here, nowhere else. |
| `docs/spec/` | Monorepo mirror. Referenced by README, CONTRIBUTING, CHARTER, CODEOWNERS. May hold extra internal drafts (e.g. `cncf-sandbox-proposal.md`). |
| `ArohaLabs/aroha-spec` | Public GitHub repo. Never edit directly. |

The old instructions here were a manual `cp` of two of the three, which is how
`docs/spec/did-method.md` ended up a full section behind the source of truth
without anyone noticing. Do not hand-copy; run the script.

## Syncing an edit out

```bash
cd spec-public
./sync.sh --check   # report drift in BOTH mirrors; exit 1 if any
./sync.sh --push    # reconcile docs/spec, then commit and push the public repo
```

`--check` is safe to run anywhere and is the right thing to wire into CI or a
pre-launch checklist. Internal-only files (`PUBLISH.md`, `sync.sh`,
`w3c-registration/SUBMIT.md`) are excluded from the public mirror automatically.

## State

- Published: 2026-07-15 (initial push by maintainer; cleaned + org-swept same day)
- Issues enabled, `rfc` label created (proposals for 1.x extensions)
- 2026-07-27: `sync.sh` now checks `docs/spec/` as well, so the manual-copy
  drift risk noted below is closed. `aroha-1.0.html` added to the public mirror
  so both ReSpec documents publish together.
