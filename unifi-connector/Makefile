.PHONY: format lint test check upgrade image

IMAGE ?= ghcr.io/edepree/isc-unifi-connector
VERSION := $(shell uv version --short)

format:
	uv run ruff format .
	uv run ruff check --fix .

lint:
	uv run --locked ruff format --check .
	uv run --locked ruff check .
	uv run --locked ty check

test:
	uv run --locked pytest

check: lint test

upgrade:
	uv lock --upgrade
	uv sync

image:
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .
