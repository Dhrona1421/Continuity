FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN groupadd --system ghostsoc && useradd --system --gid ghostsoc --home /app ghostsoc
COPY pyproject.toml requirements.lock ./
RUN pip install --no-cache-dir -c requirements.lock .
COPY alembic.ini ./
COPY alembic ./alembic
COPY rules ./rules
COPY app ./app
RUN mkdir -p /var/lib/ghostsoc/reports /var/lib/ghostsoc/evidence && chown -R ghostsoc:ghostsoc /app /var/lib/ghostsoc
USER ghostsoc
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3)"
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
