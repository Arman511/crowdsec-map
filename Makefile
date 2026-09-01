COMPOSE ?= docker compose
COMPOSE_FILE ?= docker-compose.yml
DEMO_COMPOSE_FILE ?= docker-compose.demo.yml
SERVICE ?= crowdsec-map

.PHONY: help install-hooks build build-no-cache up down restart logs ps pull clean

help:
	@echo "Usage: make <target> [COMPOSE_FILE=...] [SERVICE=...]"
	@echo ""
	@echo "Targets:"
	@echo "  build           Build images with docker compose"
	@echo "  install-hooks   Enable the repository pre-commit checks"
	@echo "  build-no-cache  Build images without cache"
	@echo "  up              Start stack in detached mode"
	@echo "  down            Stop and remove stack"
	@echo "  restart         Recreate and restart stack"
	@echo "  logs            Follow service logs"
	@echo "  ps              Show compose services status"
	@echo "  pull            Pull latest base images"
	@echo "  clean           Stop stack and remove orphan containers"

install-hooks:
	git config core.hooksPath .githooks

build:
	$(COMPOSE) -f $(COMPOSE_FILE) build

build-no-cache:
	$(COMPOSE) -f $(COMPOSE_FILE) build --no-cache

up:
	$(COMPOSE) -f $(COMPOSE_FILE) up

serve:
	$(COMPOSE) -f $(COMPOSE_FILE) up -d

down:
	$(COMPOSE) -f $(COMPOSE_FILE) down

restart:
	$(COMPOSE) -f $(COMPOSE_FILE) up -d --build --force-recreate

logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f $(SERVICE)

ps:
	$(COMPOSE) -f $(COMPOSE_FILE) ps

pull:
	$(COMPOSE) -f $(COMPOSE_FILE) pull

clean:
	$(COMPOSE) -f $(COMPOSE_FILE) down --remove-orphans

demo:
	$(COMPOSE) -f $(DEMO_COMPOSE_FILE) up --build --force-recreate
