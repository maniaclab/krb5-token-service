FROM ghcr.io/prefix-dev/pixi:latest AS builder

WORKDIR /app
COPY . .

# Install only the service feature, not dev. kinit/klist come from the
# conda-forge `krb5` package (see pixi.toml) — like voms-token-service's
# `voms` package, the Kerberos clients ride in the same pixi environment as
# the Python service, so no extra package-manager step is needed in the
# runtime stage below.
RUN pixi install --frozen --environment service

# Capture pixi's full activation (PATH, and anything else the environment
# needs) as a static entrypoint script, so the final image needs no pixi
# binary at runtime.
RUN echo '#!/bin/bash' > /app/entrypoint.sh && \
    pixi shell-hook --manifest-path /app/pixi.toml --environment service -s bash >> /app/entrypoint.sh && \
    echo 'exec "$@"' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Final stage: debian:bookworm-slim, matching voms-token-service's
# Containerfile layout (and staying binary-compatible with the pixi-built
# environment copied from the builder stage). ca-certificates is needed at
# runtime for httpx to verify the broker's JWKS TLS endpoint.
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Keep the same absolute path as the builder stage: the entrypoint script's
# activation exports (and any console-script shebangs, e.g. uvicorn) are
# baked in at this exact path, and relocating the env directory breaks them.
COPY --from=builder /app/.pixi/envs/service /app/.pixi/envs/service
COPY --from=builder /app/src /app/src
COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh
COPY etc/krb5.conf /app/etc/krb5.conf

ENV PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KRB5_CONFIG=/app/etc/krb5.conf

# Unlike voms-token-service (which needs runAsUser 0 + CAP_DAC_READ_SEARCH
# to read arbitrary users' NFS-mounted certificate files), kinit needs no
# on-disk user credential — the password on the wire is the entire
# credential — so this service runs as a fixed unprivileged uid for its
# whole lifetime. See charts/krb5-token-service/values.yaml.
USER 1000:1000

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "krb5_token_service.app:app", "--host", "0.0.0.0", "--port", "8080"]
