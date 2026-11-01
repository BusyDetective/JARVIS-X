# Validation image for JARVIS-X isolated validation (Phase 8).
#
# Build it ONCE, with network access, from the project root:
#     docker build -t jarvisx-validation:1 -f docker/validation.Dockerfile .
#   (or: podman build -t jarvisx-validation:1 -f docker/validation.Dockerfile .)
#
# At validation time the container is started WITHOUT network (--network none), as user 65534, with a read-only
# root filesystem, all capabilities dropped and no host mounts except the candidate snapshot (read-only).
# Nothing is installed at validation time, so every dependency the test suite and pyflakes need must be here.
#
# Production hardening: pin the base image by digest (FROM python:3.12-slim@sha256:...) and rebuild on a schedule.
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt requirements-dev.txt /tmp/
RUN pip install -r /tmp/requirements-dev.txt && rm -rf /tmp/requirements*.txt

# Mount points used by the sandbox profile; /work and /tmp are mounted as tmpfs at run time.
RUN mkdir -p /work /snapshot

USER 65534:65534
WORKDIR /work
