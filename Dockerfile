ARG PYTHON_IMAGE=python:3.13.7-slim@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689
FROM ${PYTHON_IMAGE}

# The default multi-platform digest was verified on 2026-08-24. Override PYTHON_IMAGE
# only with another version-and-digest-pinned official image.

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

USER 65532:65532
CMD ["python", "-m", "aegis_ot"]
