# Single runtime image for all host containers. Each host runs the same image with a
# per-host `command` selecting which host in the mounted config to serve.
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY rangefinder ./rangefinder
RUN pip install --no-cache-dir .

# Non-root facade user. Binding privileged ports is granted at runtime via the
# net.ipv4.ip_unprivileged_port_start sysctl set per-container in the compose file.
RUN useradd --system --uid 10001 --no-create-home ranger
USER 10001

# Config is bind-mounted read-only at /range/config.json by the generated compose file.
ENTRYPOINT ["rangefinder"]
CMD ["--help"]
