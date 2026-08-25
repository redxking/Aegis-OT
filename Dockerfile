ARG PYTHON_IMAGE=python:3.13.7-slim@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689
FROM ${PYTHON_IMAGE}

# The default multi-platform digest was verified on 2026-08-24. Override PYTHON_IMAGE
# only with another version-and-digest-pinned official image.

WORKDIR /app
COPY pyproject.toml requirements.lock README.md LICENSE ./
COPY src ./src
ARG AEGIS_INSTALL_TARGET=.
RUN if [ "${AEGIS_INSTALL_TARGET}" != "." ] \
        && [ "${AEGIS_INSTALL_TARGET}" != ".[simulation]" ]; then \
      echo "AEGIS_INSTALL_TARGET must be . or .[simulation]" >&2; \
      exit 2; \
    fi \
    && python -m pip install \
      --no-cache-dir \
      --constraint requirements.lock \
      "${AEGIS_INSTALL_TARGET}"

USER 65532:65532
CMD ["python", "-m", "aegis_ot"]
