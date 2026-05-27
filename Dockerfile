# Pulse — production Docker image
# ---------------------------------
# Multi-stage build kept single-stage on purpose: Pulse has no compiled
# assets and the wheel install footprint isn't large enough to justify
# a separate runtime stage. Slim base + non-root runtime user is the
# whole security story.

FROM python:3.11-slim

LABEL org.opencontainers.image.title="Pulse" \
      org.opencontainers.image.description="Open-source Windows event log analyzer + threat detection dashboard" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/barrytd/Pulse"

# Don't byte-compile .pyc and don't buffer stdout — both matter inside
# containers so logs stream to `docker logs` immediately and the image
# stays a few hundred KB smaller.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PULSE_ENV=production \
    PORT=8000

# Install runtime dependencies. We use requirements-lock.txt (exact
# pins) inside the image so production deploys ship the same byte-for-
# byte versions the CI tests pass against. See README "Production
# deploys" + CHANGELOG 2026-05-14 for the rationale.
WORKDIR /app
COPY requirements-lock.txt ./
RUN pip install --no-cache-dir -r requirements-lock.txt

# Copy only the runtime surface — Dockerfile + docker-compose + tests
# + samples + dist artifacts are all excluded via .dockerignore.
COPY pulse/ ./pulse/
COPY scripts/ ./scripts/
COPY main.py ./main.py

# Drop root. The non-root user owns /app so it can read its own code +
# write the SQLite file when DATABASE_URL is unset (single-container
# demo mode). When the docker-compose.yml below points at Postgres,
# /app is read-only at runtime.
RUN groupadd --system pulse && \
    useradd --system --no-create-home --gid pulse pulse && \
    chown -R pulse:pulse /app
USER pulse

# Entrypoint script handles "wait for Postgres" + creates the seed
# admin user on first boot when PULSE_ADMIN_EMAIL / _PASSWORD are set.
COPY --chown=pulse:pulse docker/entrypoint.sh /usr/local/bin/pulse-entrypoint
# `chmod` doesn't survive the `--chown` copy on some Docker builds;
# python -c keeps the image cross-platform reproducible.
RUN python -c "import os, stat; os.chmod('/usr/local/bin/pulse-entrypoint', stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)"

EXPOSE 8000

# uvicorn directly would be one fewer layer of indirection, but
# main.py's --api code path is what every other deployment shape uses
# (local dev, --watch, CI). Keeping the entrypoint identical here means
# anything that works in dev works in the container.
ENTRYPOINT ["/usr/local/bin/pulse-entrypoint"]
CMD ["python", "main.py", "--api", "--host", "0.0.0.0", "--port", "8000"]
