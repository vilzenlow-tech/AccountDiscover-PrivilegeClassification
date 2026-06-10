.PHONY: up down logs backend-sh worker-sh fe-sh migrate seed test lint

up:
	docker compose up -d --build

down:
	docker compose down -v

logs:
	docker compose logs -f --tail=200

backend-sh:
	docker compose exec backend bash

worker-sh:
	docker compose exec worker bash

fe-sh:
	docker compose exec frontend sh

migrate:
	docker compose exec backend alembic upgrade head

seed:
	docker compose exec backend python -m app.seed

test:
	docker compose exec backend pytest -q

lint:
	docker compose exec backend ruff check app
	docker compose exec frontend npm run lint
