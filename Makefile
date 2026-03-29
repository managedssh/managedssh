APP := managedssh
LOCAL_BIN := $(HOME)/.local/bin

.PHONY: help build run test fmt tidy install clean

help:
	@printf "Available targets:\n"
	@printf "  make build    Build the binary\n"
	@printf "  make run      Run the app\n"
	@printf "  make test     Run tests\n"
	@printf "  make fmt      Format Go files\n"
	@printf "  make tidy     Tidy Go modules\n"
	@printf "  make install  Install to GOBIN/GOPATH/bin, or ~/.local/bin fallback\n"
	@printf "  make clean    Remove build artifacts and Go caches\n"

build:
	go build -o $(APP) .

run:
	go run .

test:
	go test ./...

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

clean:
	rm -f $(APP)
	rm -f *.test *.out coverage.out
	rm -rf dist bin
	go clean -cache -testcache -fuzzcache -modcache
