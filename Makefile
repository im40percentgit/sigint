.PHONY: build test lint fmt frontend docker clean

# Build release binary (includes frontend)
build: frontend
	cargo build --release

# Build frontend
frontend:
	cd crates/sigint-web/frontend && npm ci && npm run build

# Run all tests
test: frontend
	cargo test --workspace

# Run clippy
lint: frontend
	cargo clippy --workspace -- -D warnings

# Check formatting
fmt:
	cargo fmt --all -- --check

# Build Docker image
docker:
	docker build -t sigint .

# Start with docker-compose
up:
	docker-compose up -d

# Clean build artifacts
clean:
	cargo clean
	rm -rf crates/sigint-web/frontend/node_modules
