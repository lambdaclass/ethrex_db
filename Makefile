.PHONY: build lint test clean bench profile

help: ## 📚 Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## 🔨 Build the client
	cargo build --workspace

lint: ## 🧹 Linter check
	cargo clippy --all-targets --all-features --workspace -- -D warnings

test: ## 🧪 Run each crate's tests
	cargo test --workspace

clean: ## 🧹 Remove build artifacts
	cargo clean

bench: ## 📊 Run benchmarks
	cargo bench --bench db_benchmark --features="libmdbx-benchmark"

profile: ## 🔍 Run samply profile
	cargo build --profile release-with-debug --example profiling
	samply record -r 10000 ./target/release-with-debug/examples/profiling
