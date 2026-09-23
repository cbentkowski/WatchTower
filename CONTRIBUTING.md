# Contributing to WatchTower

## Branch workflow

The `main` branch represents the current accepted release state.

All changes must be developed on a dedicated branch and merged into `main` through a pull request. Do not make routine commits directly on `main`, even while GitHub branch protection is unavailable for this private repository.

Use short branch names that describe the work, such as:

- `feature/nvd-cpe-search`
- `fix/notification-schedule`
- `docs/deployment-guide`

Before opening a pull request:

1. Rebase or merge the current `main` branch into the working branch.
2. Run the automated test suite.
3. Document user-visible changes in `CHANGELOG.md`.
4. Confirm that credentials, secret files, scan state, logs, and local dependency caches are not committed.

Pull requests should explain what changed, why it changed, how it was tested, and any remaining operational or security considerations.
