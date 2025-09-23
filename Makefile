.PHONY: dev lint format test type

dev:
	python -m app.cli runserver --reload

lint:
	ruff check .

format:
	ruff format .

type:
	mypy src

test:
	pytest
