# HappyMining agent - convenience targets. Run from the agent/ directory.
# No network access is needed: the module has no third-party dependency.

.PHONY: check fmt vet test build deb

check: fmt vet test

fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

test:
	go test ./... -race

build:
	scripts/build.sh

# Builds the binaries and the .deb, then scans the package.
deb:
	scripts/build-deb.sh
