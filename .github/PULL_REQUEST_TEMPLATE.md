<!-- Thank you. Genuinely — this project is looking for maintainers, and three
     merged pull requests of substance is the whole bar. See GOVERNANCE.md. -->

## What this changes, and why

<!-- The why matters more than the what; the diff already says what. If it
     fixes a bug, what was the bug actually caused by? -->

## Checklist

- [ ] `make test` passes
- [ ] `gofmt -l .` prints nothing and `go vet ./...` is clean
- [ ] Commits are signed off (`git commit -s`) — see CONTRIBUTING.md
- [ ] No new entry in `go.mod`
- [ ] If this adds a capability: reachable from the CLI, the browser and MCP, or a written reason in the coverage table
- [ ] If this fixes a bug: a test that fails without the fix
