FROM python:3.12-slim

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        nano \
        openssh-client \
        bash-completion \
        locales \
    && rm -rf /var/lib/apt/lists/* \
    && echo "en_US.UTF-8 UTF-8" > /etc/locale.gen \
    && locale-gen en_US.UTF-8 \
    && update-locale LANG=en_US.UTF-8

# Add a non-root user and switch to it
RUN useradd -m dev \
    && mkdir -p /home/dev/.vscode-server /workspace/.venv \
    && chown -R dev:dev /workspace /home/dev/.vscode-server /workspace/.venv

USER dev

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8
