# Build website
web:
	cd site; bun run build

# Requirements
requirements:
	cd site; bun install
	go mod tidy

# Copy site assets
assets: web
	rm -rf internal/assets/dist
	mkdir -p internal/assets/dist
	cp -r site/dist/* internal/assets/dist

# Run development binary
run: assets
	go run main.go

# Run development binary without compiling the frontend
run-skip-web:
	go run main.go

# Test
test:
	go test ./...

# Build
build: assets
	go build -o tinyauth

# Build the binary without compiling the frontend
build-skip-web:
	go build -o tinyauth