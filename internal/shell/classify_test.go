// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shell

import (
	"strings"
	"testing"
)

// Every command is one kind, from its program and arguments; what is not
// known is taken as writing, and a shell as anything.
func TestEachCommandIsAKind(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		want string
	}{
		{"ls -la", "reads"},
		{"cat go.mod", "reads"},
		{"grep -rn TODO .", "reads"},
		{"git status", "reads"},
		{"git -C sub log --oneline", "reads"},
		{"git diff HEAD~1", "reads"},
		{"git branch", "reads"},
		{"git branch -a", "reads"},
		{"git branch new-thing", "writes"},
		{"git branch -D old", "destroys"},
		{"git add .", "writes"},
		{"git commit -m tidy", "writes"},
		{"git commit --amend -m tidy", "destroys"},
		{"git reset --hard HEAD~1", "destroys"},
		{"git reset HEAD~1", "destroys"},
		{"git clean -fd", "destroys"},
		{"git clean -n", "reads"},
		{"git checkout -- file.go", "destroys"},
		{"git checkout main", "writes"},
		{"git restore file.go", "destroys"},
		{"git rebase main", "destroys"},
		{"git stash", "writes"},
		{"git stash drop", "destroys"},
		{"git fetch origin", "writes, reaches the network"},
		{"git pull", "writes, reaches the network"},
		{"git push origin main", "writes, reaches the network"},
		{"git push --force origin main", "destroys, reaches the network"},
		{"git push origin +main", "destroys, reaches the network"},
		{"git ls-remote origin", "reaches the network"},
		{"git -c alias.x=!sh x", "destroys, reaches the network"},
		{"git config user.name", "writes"},
		{"git config --get user.name", "reads"},
		{"go vet ./...", "reads"},
		{"go test ./...", "writes"},
		{"go build ./cmd/x", "writes"},
		{"go mod download", "writes, reaches the network"},
		{"go install ./cmd/x", "writes"},
		{"go install example.com/x@latest", "writes, reaches the network"},
		{"go env", "reads"},
		{"go env -w GOPRIVATE=x", "writes"},
		{"gofmt -l .", "reads"},
		{"gofmt -w .", "writes"},
		{"npm install", "writes, reaches the network"},
		{"npm test", "writes"},
		{"npm ls", "reads"},
		{"pip install requests", "writes, reaches the network"},
		{"pip list", "reads"},
		{"sed s/a/b/ f", "reads"},
		{"sed -i s/a/b/ f", "writes"},
		{"sed -i.bak s/a/b/ f", "writes"},
		{"sort -o out in", "writes"},
		{"find . -name *.go", "reads"},
		{"find . -name *.tmp -delete", "destroys"},
		{"find . -exec rm {} ;", "destroys, reaches the network"},
		{"rm notes.txt", "destroys"},
		{"rm -rf build", "destroys"},
		{"curl https://example.com", "reaches the network"},
		{"curl -o page https://example.com", "writes, reaches the network"},
		{"wget https://example.com", "writes, reaches the network"},
		{"sh -c ls", "destroys, reaches the network"},
		{"bash script.sh", "destroys, reaches the network"},
		{"env FOO=1 ls", "destroys, reaches the network"},
		{"xargs rm", "destroys, reaches the network"},
		{"python3 script.py", "writes"},
		{"make", "writes"},
		{"somethingunknown --flag", "writes"},
	} {
		f := strings.Fields(c.cmd)
		if got := Classify(f[0], f[1:]).String(); got != c.want {
			t.Errorf("%s: %s, want %s", c.cmd, got, c.want)
		}
	}
}
