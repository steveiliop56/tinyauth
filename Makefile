# Build website
web:
	cd site; bun run build

# Copy site assets
assets: web
	rm -rf internal/assets/dist
	mkdir -p internal/assets/dist
	cp -r site/dist/* internal/assets/dist

# Run development binary
run: assets
	go run main.go

# Test
test:
	go test ./...

# Build
build: assets
	go build -o tinyauth

# Build no site
build-skip-web:
	go build -o tinyauth