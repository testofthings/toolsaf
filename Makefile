.PHONY: check-version

check-version: compare-pyproject-version

# Make sure pyproject.toml has been updated to match RELEASE_TAG.
# Checks the line 'version = "X.X..."' in section [project].
compare-pyproject-version: compare-changelog
	@PYPROJECT_VERSION=$$(grep -m 1 '^version' pyproject.toml | tr -d " \t" | sed -E 's/version="([^"]+)"/\1/'); \
	echo "Found pyproject.toml version: v$$PYPROJECT_VERSION"; \
	if [ "v$$PYPROJECT_VERSION" != "$(RELEASE_TAG)" ]; then \
		echo "Error: RELEASE_TAG $(RELEASE_TAG) does not match pyproject.toml version $$PYPROJECT_VERSION"; \
		exit 1; \
	else \
		echo "pyproject.toml has been updated to match RELEASE_TAG"; \
	fi

# Make sure CHANGELOG.md has been updated to match RELEASE_TAG.
# Checks that first line starting with '## v'.
# Format should be ## vX.X... for CHANGELOG entries.
compare-changelog: ensure-release-tag
	@CHANGELOG_VERSION=$$(grep -m 1 '^## v' CHANGELOG.md | sed 's/^## //'); \
	echo "Found CHANGELOG version: $$CHANGELOG_VERSION"; \
	if [ "$$CHANGELOG_VERSION" != "$(RELEASE_TAG)" ]; then \
		echo "Error: RELEASE_TAG $(RELEASE_TAG) does not match CHANGELOG version $$CHANGELOG_VERSION"; \
		exit 1; \
	else \
		echo "CHANGELOG.md has been updated to match RELEASE_TAG\n"; \
	fi

# Make sure RELEASE_TAG is set.
ensure-release-tag:
	@if [ -z "$(RELEASE_TAG)" ]; then \
		echo "Error: No RELEASE_TAG given"; \
		exit 1; \
	fi
