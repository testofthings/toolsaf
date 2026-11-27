# Installs the wheel from dist/
FROM python:3.14-slim@sha256:22eafb370920ad8b429e0aec3fff433e0669968519f5d60469d83729c138b28b

LABEL org.opencontainers.image.source="https://github.com/testofthings/toolsaf" \
      org.opencontainers.image.description="Tool-Driven Security Assessment Framework" \
      org.opencontainers.image.licenses="MIT"

# Statements are run from a mounted folder, keep it free of __pycache__
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN --mount=type=bind,source=dist,target=/tmp/dist \
    pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore /tmp/dist/toolsaf-*.whl \
    && useradd --create-home --uid 1000 toolsaf

USER 1000:1000
WORKDIR /work
