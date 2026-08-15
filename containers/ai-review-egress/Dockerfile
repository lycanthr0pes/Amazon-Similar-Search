FROM python@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d

LABEL org.opencontainers.image.title="amazon-explorer fixed OpenAI egress gateway"
LABEL org.opencontainers.image.description="Credential-free one-shot TCP gateway to api.openai.com:443"

ENV HOME=/nonexistent \
    AI_REVIEW_EGRESS_GATEWAY=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONHASHSEED=0 \
    PATH=/usr/local/bin:/usr/bin:/bin

WORKDIR /opt/ai-review/bin
COPY tools/ai_review/egress_gateway.py ./egress-gateway
RUN chmod 0555 /opt/ai-review /opt/ai-review/bin \
    && chmod 0555 /opt/ai-review/bin/egress-gateway

USER 65531:65531
EXPOSE 8443
ENTRYPOINT ["/opt/ai-review/bin/egress-gateway"]
