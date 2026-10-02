# Atajos de desarrollo. En Windows puedes usar `make` (con Git Bash / choco)
# o copiar los comandos a mano.

.PHONY: install dev test lint format type clean

install:          ## Instalar la herramienta
	pip install -e .

dev:              ## Instalar con dependencias de desarrollo
	pip install -e ".[dev,explain]"

test:             ## Ejecutar los tests
	pytest

lint:             ## Comprobar estilo con ruff
	ruff check src tests

format:           ## Formatear el código
	ruff format src tests

type:             ## Comprobación de tipos
	mypy src

clean:            ## Borrar cachés y artefactos temporales
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage build dist *.egg-info
