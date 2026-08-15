FROM python@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d

LABEL org.opencontainers.image.title="amazon-explorer text-only AI review broker"
LABEL org.opencontainers.image.description="Pinned packet-only OpenAI Responses client without candidate access"

ENV HOME=/nonexistent \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONHASHSEED=0 \
    PATH=/usr/local/bin:/usr/bin:/bin

WORKDIR /opt/ai-review/bin
COPY tools/ai_review/broker_entry.py ./responses-broker
RUN chmod 0555 /opt/ai-review /opt/ai-review/bin \
    && chmod 0555 /opt/ai-review/bin/responses-broker

USER 65532:65532
ENTRYPOINT ["/opt/ai-review/bin/responses-broker"]
