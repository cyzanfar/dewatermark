FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
COPY pyproject.toml README.md LICENSE UNICODE_LICENSE.txt ./
COPY src ./src
COPY eval ./eval
COPY skills ./skills
COPY schemas ./schemas
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="dewatermark" \
      org.opencontainers.image.description="Local-first text watermark assurance toolkit" \
      org.opencontainers.image.source="https://github.com/cyzanfar/text-watermark-remover" \
      org.opencontainers.image.licenses="MIT"
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --create-home --no-log-init --uid 10001 --shell /usr/sbin/nologin dewatermark \
    && install -d -o dewatermark -g dewatermark /workspace
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels dewatermark \
    && python -m pip check \
    && rm -rf /wheels
USER dewatermark
WORKDIR /workspace
EXPOSE 8765
ENTRYPOINT ["dewatermark"]
# Safe default: print local capabilities and exit. Binding a container service to
# 0.0.0.0 requires an explicitly supplied DEWATERMARK_SERVER_API_KEY.
CMD ["capabilities"]
