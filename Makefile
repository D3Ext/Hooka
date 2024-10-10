EXECUTABLE=hooka
WINDOWS=$(EXECUTABLE)_windows_amd64.exe
LINUX=$(EXECUTABLE)_linux_amd64
DARWIN=$(EXECUTABLE)_darwin_amd64

.PHONY: all clean

all: build ## Build all

build: windows linux darwin ## Build binaries

windows: $(WINDOWS) ## Build for Windows

linux: $(LINUX) ## Build for Linux

darwin: $(DARWIN) ## Build for Darwin (macOS)

$(WINDOWS):
	GOOS=windows GOARCH=amd64 go build -o build/$(WINDOWS) -ldflags="-s -w -X main.version=$(VERSION)" ./cmd/main.go

$(LINUX):
	GOOS=linux GOARCH=amd64 go build -o build/$(LINUX) -ldflags="-s -w -X main.version=$(VERSION)" ./cmd/main.go

$(DARWIN):
	GOOS=darwin GOARCH=amd64 go build -o build/$(DARWIN) -ldflags="-s -w -X main.version=$(VERSION)" ./cmd/main.go

clean: ## Remove previous build
	rm -f build/$(WINDOWS) build/$(LINUX) build/$(DARWIN)

help: ## Display available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

