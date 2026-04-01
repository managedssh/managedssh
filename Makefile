APP := managedssh
LOCAL_BIN := $(HOME)/.local/bin

.PHONY: help build run test test-race vet lint fmt tidy install uninstall clean

help:
	@printf "Available targets:\n"
	@printf "  make build    Build the binary\n"
	@printf "  make run      Run the app\n"
	@printf "  make test     Run tests\n"
	@printf "  make test-race Run tests with race detector\n"
	@printf "  make vet      Run go vet\n"
	@printf "  make lint     Run golangci-lint (if installed)\n"
	@printf "  make fmt      Format Go files\n"
	@printf "  make tidy     Tidy Go modules\n"
	@printf "  make install  Install to GOBIN/GOPATH/bin, or ~/.local/bin fallback\n"
	@printf "  make uninstall Remove installed binary\n"
	@printf "  make clean    Remove build artifacts and Go caches\n"

build:
	go build -o $(APP) .

run:
	go run .

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		printf "golangci-lint not installed; skipping lint target.\n"; \
	fi

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

tidy:
	go mod tidy

install:
	@if [ -n "$$GOBIN" ] || [ -n "$$GOPATH" ]; then \
		go install .; \
		printf "Installed via go install (GOBIN/GOPATH path).\n"; \
	else \
		mkdir -p "$(LOCAL_BIN)"; \
		GOBIN="$(LOCAL_BIN)" go install .; \
		printf "Installed to $(LOCAL_BIN).\n"; \
		case ":$$PATH:" in \
			*":$(LOCAL_BIN):"*) ;; \
			*) printf "~/.local/bin is not in path please add it to path.\n" ;; \
		esac; \
	fi

uninstall:
	@if [ -n "$$GOBIN" ]; then \
		target="$$GOBIN/$(APP)"; \
	elif [ -n "$$GOPATH" ]; then \
		target="$${GOPATH%%:*}/bin/$(APP)"; \
	else \
		target="$(LOCAL_BIN)/$(APP)"; \
	fi; \
	if [ -f "$$target" ]; then \
		rm -f "$$target"; \
		printf "Removed $$target\n"; \
	else \
		printf "No installed binary found at $$target\n"; \
	fi

clean:
	rm -f $(APP)
	rm -f *.test *.out coverage.out
	rm -rf dist bin
	go clean -cache -testcache -fuzzcache -modcache
