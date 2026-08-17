FROM python:3.12-slim AS builder
WORKDIR /build
COPY . .
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 dewatermark
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER dewatermark
EXPOSE 8765
ENTRYPOINT ["dewatermark"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8765"]
