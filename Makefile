BINARY=evilginx-dashboard

.PHONY: build run clean vet

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY) .

# Compila para el servidor típico (Linux amd64) desde cualquier host
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY) .

run: build
	./$(BINARY) -addr 127.0.0.1:8090

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
