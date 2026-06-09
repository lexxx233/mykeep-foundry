VERSION ?= 0.1.0-dev
TARGETS := windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet cross guard clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/foundry ./cmd/foundry

test:
	go test ./...

vet:
	go vet ./...

cross:
	@mkdir -p dist
	@for t in $(TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  echo "  $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	    go build -trimpath -ldflags "$(LDFLAGS)" -o dist/foundry-$$os-$$arch$$ext ./cmd/foundry || exit 1; \
	done
	@echo "built $$(ls dist | wc -l) binaries in dist/"

# guard proves zero CGo across the whole dependency graph — the load-bearing portability
# claim: the QuickJS sandbox runs via pure-Go wazero, so the same static binary works on
# every OS with no host toolchain.
guard:
	CC=/bin/false CGO_ENABLED=0 go build ./... && echo "no-cgo build OK"

clean:
	rm -rf bin dist
