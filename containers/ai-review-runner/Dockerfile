FROM ghcr.io/astral-sh/uv@sha256:df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c AS uv

FROM python@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d

LABEL org.opencontainers.image.title="amazon-explorer offline AI review runner"
LABEL org.opencontainers.image.description="Pinned Python and uv dependencies for network-denied deterministic gates"

COPY --from=uv /uv /uvx /usr/local/bin/

# Harness regression tests create disposable Git repositories.  Pin the complete package set so
# a rebuild fails instead of silently selecting newer host tools; the final OCI digest remains the
# runtime trust anchor recorded in runtime-manifest.json.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git=1:2.39.5-0+deb12u3 \
        git-man=1:2.39.5-0+deb12u3 \
        libbrotli1=1.0.9-2+b6 \
        libcurl3-gnutls=7.88.1-10+deb12u15 \
        liberror-perl=0.17029-2 \
        libexpat1=2.5.0-1+deb12u2 \
        libgdbm-compat4=1.23-3 \
        libgssapi-krb5-2=1.20.1-2+deb12u5 \
        libk5crypto3=1.20.1-2+deb12u5 \
        libkeyutils1=1.6.3-2 \
        libkrb5-3=1.20.1-2+deb12u5 \
        libkrb5support0=1.20.1-2+deb12u5 \
        libldap-2.5-0=2.5.13+dfsg-5 \
        libnghttp2-14=1.52.0-1+deb12u3 \
        libperl5.36=5.36.0-7+deb12u3 \
        libpsl5=0.21.2-1 \
        librtmp1=2.4+20151223.gitfa8646d.1-2+b2 \
        libsasl2-2=2.1.28+dfsg-10 \
        libsasl2-modules-db=2.1.28+dfsg-10 \
        libssh2-1=1.10.0-3+b1 \
        perl=5.36.0-7+deb12u3 \
        perl-modules-5.36=5.36.0-7+deb12u3 \
    && rm -rf /var/lib/apt/lists/*

ENV UV_PROJECT_ENVIRONMENT=/opt/ai-review-runtime/.venv \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_FROZEN=1 \
    UV_NO_CACHE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPYCACHEPREFIX=/tmp/pycache \
    PYTEST_ADDOPTS="-p no:cacheprovider" \
    RUFF_CACHE_DIR=/tmp/ruff-cache \
    HOME=/nonexistent \
    PATH=/opt/ai-review-runtime/.venv/bin:/usr/local/bin:/usr/bin:/bin

WORKDIR /opt/ai-review-runtime
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project \
    && find /opt/ai-review-runtime -type d -exec chmod 0555 {} + \
    && find /opt/ai-review-runtime -type f -exec chmod 0444 {} + \
    && find /opt/ai-review-runtime/.venv/bin -type f -exec chmod 0555 {} +

# Runtime execution is offline. The build phase may fetch only artifacts pinned by uv.lock.
ENV UV_OFFLINE=1

WORKDIR /candidate
USER 65534:65534

CMD ["python", "--version"]
