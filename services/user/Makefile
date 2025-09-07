#services/user/Makefile
include ./cmd/.env
export

# File path resolution
PROTO_DIR := ./proto
GEN_DIR := ./proto/genproto

# Proto file discovery
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)

.PHONY: gen clean migration run

run:
	@cd cmd && air

gen:
	@echo "generating files..."
	@mkdir -p $(GEN_DIR)
	protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=paths=source_relative:$(GEN_DIR) \
		--go-grpc_out=paths=source_relative:$(GEN_DIR) \
		$(PROTO_FILES)
	@echo "file generation complete!"

clean:
	@echo "Removing generated files..."
	@find $(GEN_DIR) -name 'user*' -delete
	@echo "Clean complete."

createdb:
	@echo "Creating database if it doesn't exist..."
	@mysql -u$(DB_USER) -p$(DB_PASSWORD) -h$(DB_HOST) -P$(DB_PORT) -e "CREATE DATABASE IF NOT EXISTS \`$(DB_NAME)\`;"

dropdb:
	@echo "WARNING: This will permanently delete the $(DB_NAME) database!"
	@read -p "Are you sure? (y/N) " confirm && [ $$confirm = y ] || exit 1
	@mysql -u$(DB_USER) -p$(DB_PASSWORD) -h$(DB_HOST) -P$(DB_PORT) \
		-e "DROP DATABASE IF EXISTS \`$(DB_NAME)\`;" && \
	echo "Database $(DB_NAME) deleted"

migration:
	@migrate create -ext sql -dir ./cmd/migrate/migrations $(filter-out $@,$(MAKECMDGOALS))

migrate-up:
	@go run ./cmd/migrate/main.go up

migrate-down:
	@go run ./cmd/migrate/main.go down
