# Part 3: Go firewall scanner. Recipes run from the repository root.
FWSCAN_DIR     := 03-firewall-scanner
FWSCAN_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

FMT_TARGETS  += fwscan-fmt
LINT_TARGETS += fwscan-lint
TEST_TARGETS += fwscan-test

.PHONY: fwscan-build fwscan-fmt fwscan-lint fwscan-test fwscan-mock

fwscan-build: ## Build the firewall scanner into 03-firewall-scanner/bin/fwscan
	cd $(FWSCAN_DIR) && go build -trimpath -ldflags "-s -w -X main.version=$(FWSCAN_VERSION)" -o bin/fwscan ./cmd/fwscan

fwscan-fmt: ## Format the Go code of the firewall scanner
	cd $(FWSCAN_DIR) && gofmt -w .

fwscan-lint: ## Run golangci-lint on the firewall scanner
	cd $(FWSCAN_DIR) && golangci-lint run --config ../.golangci.yml ./...

fwscan-test: ## Run the firewall scanner tests with the race detector
	cd $(FWSCAN_DIR) && go test -race -count=1 ./...

fwscan-mock: ## Run the firewall scanner with built-in mock data
	cd $(FWSCAN_DIR) && go run ./cmd/fwscan --mock
