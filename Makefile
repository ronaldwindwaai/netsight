.PHONY: dev security tree
dev:
	docker compose -f infrastructure/compose/docker-compose.dev.yml up -d

security:
	bash scripts/security-verify.sh

tree:
	find . -maxdepth 4 -type f | sort
