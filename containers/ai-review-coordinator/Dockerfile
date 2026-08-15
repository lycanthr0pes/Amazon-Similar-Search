FROM ghcr.io/astral-sh/uv@sha256:df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c AS uv

FROM python@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d

LABEL org.opencontainers.image.title="amazon-explorer AI review coordinator"
LABEL org.opencontainers.image.description="Pinned candidate-free runtime for policy and attestation validation"

COPY --from=uv /uv /uvx /usr/local/bin/

# Policy inspection requires Git, while the coordinator Python dependency set is deliberately
# smaller than the application environment. Package versions and the final OCI digest are both
# release inputs; an unavailable exact package version must fail the build.
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

ENV VIRTUAL_ENV=/opt/ai-review-runtime/.venv \
    HOME=/nonexistent \
    PATH=/opt/ai-review-runtime/.venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONHASHSEED=0

WORKDIR /opt/ai-review-runtime
COPY containers/ai-review-coordinator/requirements.txt ./requirements.txt
RUN uv venv "$VIRTUAL_ENV" \
    && uv pip install --python "$VIRTUAL_ENV/bin/python" --no-deps --requirement requirements.txt \
    && "$VIRTUAL_ENV/bin/python" -I -c \
        'import cryptography, pydantic; print(cryptography.__version__, pydantic.__version__)'

WORKDIR /opt/ai-review-app
COPY tools ./tools
RUN mkdir -p /signing \
    && chown 65532:65532 /signing \
    && chmod 0700 /signing \
    && find /opt/ai-review-runtime /opt/ai-review-app -type d -exec chmod 0555 {} + \
    && find /opt/ai-review-runtime /opt/ai-review-app -type f -exec chmod 0444 {} + \
    && find /opt/ai-review-runtime/.venv/bin -type f -exec chmod 0555 {} +

WORKDIR /
USER 65532:65532
ENTRYPOINT ["/opt/ai-review-runtime/.venv/bin/python", "-I", "/opt/ai-review-app/tools/ai_review/coordinator_main.py"]
