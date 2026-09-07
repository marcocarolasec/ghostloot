BINARY=evilginx-dashboard

.PHONY: build run clean vet test install-cli

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY) .

# Compila para el servidor típico (Linux amd64) desde cualquier host
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY) .

run: build
	./$(BINARY) -addr 127.0.0.1:8090 -db /root/.evilginx/data.db

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

install-cli:
	./install-local.sh
