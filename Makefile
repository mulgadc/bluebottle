GO_PROJECT_NAME := bluebottle
SHELL := /bin/bash

export GOFIPS140 := v1.0.0

# Quiet-mode filters (active when QUIET=1, set by preflight via recursive make)
# Note: grep pipelines use PIPESTATUS[0] so the exit status of `go test`
# propagates through the filter — otherwise a test failure is swallowed by
# grep's own (success) exit code and preflight prints "passed" on red.
ifdef QUIET
  _Q     = @
  _COVQ  = 2>&1 | { grep -Ev '^\s*(ok|PASS|\?|=== RUN|--- PASS:)\s' | grep -v 'coverage: 0\.0%' || true; }; exit $${PIPESTATUS[0]}
  _RACEQ = 2>&1 | { grep -Ev '^\s*(ok|PASS|\?|=== RUN|--- PASS:)\s' || true; }; exit $${PIPESTATUS[0]}
else
  _Q     =
  _COVQ  =
  _RACEQ =
endif

# Preflight — runs the same checks as GitHub Actions (lint + vuln + tests).
# Use this before committing to catch CI failures locally. There is no build
# target: bluebottle is a library and produces no binaries.
preflight:
	@$(MAKE) --no-print-directory QUIET=1 lint govulncheck test-cover diff-coverage
	@echo -e "\n ✅ Preflight passed — safe to commit."

# Run unit tests
test:
	@echo -e "\n....Running tests for $(GO_PROJECT_NAME)...."
	go test -timeout 120s ./...

# Run unit tests with coverage profile
COVERPROFILE ?= coverage.out
test-cover:
	@echo -e "\n....Running tests with coverage for $(GO_PROJECT_NAME)...."
	$(_Q)go test -timeout 120s -coverprofile=$(COVERPROFILE) -covermode=atomic ./... $(_COVQ)
	@scripts/check-coverage.sh $(COVERPROFILE) $(QUIET)

# Run unit tests with race detector
test-race:
	@echo -e "\n....Running tests with race detector for $(GO_PROJECT_NAME)...."
	$(_Q)go test -race -timeout 300s ./... $(_RACEQ)

# Check that new/changed code meets coverage threshold (runs tests first)
diff-coverage: test-cover
	@QUIET=$(QUIET) scripts/diff-coverage.sh $(COVERPROFILE)

# Lint all Go code via golangci-lint (replaces check-format, vet, gosec, staticcheck)
lint:
	@echo "Running golangci-lint..."
	$(_Q)golangci-lint run ./...
	@echo "  golangci-lint ok"

# Auto-fix all linter issues that have fixers
fix:
	golangci-lint run --fix ./...

# Govulncheck — dependency vulnerability scanning (not covered by golangci-lint)
govulncheck:
	@echo "Running govulncheck..."
	$(_Q)go tool govulncheck ./...
	@echo "  govulncheck ok"

# NilAway — advisory nil-panic analysis. Not in preflight: it has a known
# false-positive rate, so findings are triaged by hand rather than gating commits.
nilaway:
	@echo "Running nilaway..."
	$(_Q)go tool nilaway -include-pkgs=github.com/mulgadc/bluebottle -exclude-test-files ./...
	@echo "  nilaway ok"

clean:
	rm -f $(COVERPROFILE)

.PHONY: preflight test test-cover test-race diff-coverage lint fix govulncheck nilaway clean
