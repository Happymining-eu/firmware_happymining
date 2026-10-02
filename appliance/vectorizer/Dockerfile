# HappyMining NAS vectorizer (docs/appliance.md, section 11; README.md here).
#
# Built on the machine from the directory the package installs, never pulled:
#   docker build -t happymining/vectorizer:1 /usr/share/happymining/vectorizer
# The build needs the network (PyPI, PyTorch's CPU index, Hugging Face and
# modelscope.cn for Docling's models). The running container needs none of it.
# amd64 only: requirements.lock is resolved for x86_64 Linux.
#
# Base image: Python 3.12 on Debian 12, slim. The digest is that of the
# multi-architecture index of the tag, read from Docker Hub's API
# (https://hub.docker.com/v2/repositories/library/python/tags/3.12-slim-bookworm,
# "last_updated" 2026-09-19) on 2026-10-02. It was not pulled or built here
# (no Docker where this was written). A wrong digest makes the build fail.

# ---------------------------------------------------------------- build stage
FROM docker.io/library/python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_NO_INPUT=1 \
    HF_HOME=/tmp/hf \
    XDG_CACHE_HOME=/tmp/cache

COPY requirements.lock /tmp/requirements.lock

# Everything from PyPI with the hashes of requirements.lock (Docling 2.132.0 and
# its dependencies), then torch and torchvision from PyTorch's CPU-only index
# (no CUDA libraries: this image parses documents, it does not need a GPU).
# `pip check` fails the build if anything a package needs is missing.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-deps --require-hashes -r /tmp/requirements.lock \
 && /opt/venv/bin/pip install --no-deps --index-url https://download.pytorch.org/whl/cpu \
        torch==2.14.1 torchvision==0.29.1 \
 && /opt/venv/bin/pip check \
 && /opt/venv/bin/pip uninstall -y pip

# Docling's models, fetched now so that parsing never downloads anything:
# layout and table structure (PDF pipeline) and RapidOCR (OCR).
RUN /opt/venv/bin/docling-tools models download layout tableformer rapidocr -o /opt/docling-models

# ---------------------------------------------------------------- final stage
FROM docker.io/library/python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

# No installer and no compiler in the image; one unprivileged user. /state is
# the only directory it owns (a fresh named volume takes this owner).
RUN python -m pip uninstall -y pip \
 && groupadd --gid 10001 hmvec \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin hmvec \
 && install -d -o 10001 -g 10001 -m 0750 /state

COPY --from=build /opt/venv /opt/venv
COPY --from=build /opt/docling-models /opt/docling-models
COPY hm_vectorizer /opt/hm/hm_vectorizer
RUN /opt/venv/bin/python -m compileall -q /opt/hm/hm_vectorizer

# Writes go to /state (index database, status.json) and /tmp only: caches and
# HOME point at /tmp, the code and the models belong to root. PYTHONSAFEPATH:
# the working directory is never put on the import path.
ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/opt/hm \
    PYTHONSAFEPATH=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    TMPDIR=/tmp \
    XDG_CACHE_HOME=/tmp/cache \
    HF_HOME=/tmp/hf \
    HF_HUB_OFFLINE=1 \
    DOCLING_ARTIFACTS_PATH=/opt/docling-models

USER 10001:10001
WORKDIR /opt/hm

# Fails the build when Docling cannot parse with the files it has (offline).
RUN ["/opt/venv/bin/python", "-m", "hm_vectorizer", "selfcheck"]

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/opt/venv/bin/python", "-m", "hm_vectorizer", "healthcheck"]

ENTRYPOINT ["/opt/venv/bin/python", "-m", "hm_vectorizer"]
CMD ["serve"]
