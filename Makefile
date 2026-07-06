.PHONY: up down logs backend-sh fe-sh test lint build

up:
	docker compose up -d --build

down:
	docker compose down -v

logs:
	docker compose logs -f --tail=200

backend-sh:
	docker compose exec backend bash

fe-sh:
	docker compose exec frontend sh

test:
	docker compose exec backend npm test
	docker compose exec frontend npm run build

lint:
	docker compose exec backend npm run lint
	docker compose exec frontend npm run lint

build:
	docker compose exec backend npm run build
	docker compose exec frontend npm run build
