BINARY := gcp-iam-insights
BUILD_DIR := dist

.PHONY: build test lint fetch-roles clean

build:
	go build -o $(BUILD_DIR)/$(BINARY) .

test:
	go test ./...

lint:
	go vet ./...

fetch-roles:
	go run tools/fetch-roles/main.go

clean:
	rm -rf $(BINARY) $(BUILD_DIR)
