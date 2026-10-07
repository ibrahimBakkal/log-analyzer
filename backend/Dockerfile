# The API. Built from this folder: docker build -t log-analyzer-api backend
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv/backend

# Dependencies first, against an empty package, so that this layer is rebuilt
# only when pyproject.toml changes and not with every change to the code.
COPY pyproject.toml ./
RUN mkdir app && touch app/__init__.py && pip install -e .

COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# The server needs no privileges. /data holds the database; a volume mounted
# there for the first time takes over this owner.
RUN useradd --system --uid 10001 --no-create-home app \
    && mkdir /data /rules \
    && chown app:app /data \
    && chmod +x /usr/local/bin/docker-entrypoint.sh

ENV LOG_ANALYZER_DATABASE_URL=sqlite:////data/log_analyzer.db \
    LOG_ANALYZER_RULES_DIR=/rules

USER app
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
