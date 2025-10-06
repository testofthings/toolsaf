# ------------------------
# Config
# ------------------------
PACKAGE_NAME = toolsaf
PYPI_REPO ?= testpypi  # change to testpypi if needed
VERSION ?= 0.0      # override if needed

# ------------------------
# Targets
# ------------------------
.PHONY: all lint test mypy check-version clean build upload release

# Default: run lint, tests, mypy, version check, build, upload
all: lint test check-version build upload

# Lint with pylint
lint:
	@echo "Running pylint..."
	pylint $(PACKAGE_NAME)

# Run tests with pytest
test:
	@echo "Running tests..."
	pytest tests

# Run static type checking with mypy
mypy:
	@echo "Running mypy type checks..."
	mypy $(PACKAGE_NAME)

# Check that CHANGELOG and version match
check-version:
	@echo "Checking version consistency..."
	python check_version.py

# Remove old builds
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build dist *.egg-info

# Build package with optional manual version override
build: check-version clean
	@echo "Building package..."
	python -m build

# Upload package to PyPI or TestPyPI
upload: build
	@echo "Uploading to $(PYPI_REPO)..."
	twine upload -r $(PYPI_REPO) dist/*

# Convenience: build + upload only
release: check-version build upload
