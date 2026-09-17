# syntax=docker/dockerfile:1
#
# Bundles clamd (via the official ClamAV image) together with this repo's own
# aioclamd client, so the container can prove the two work together end to
# end (see docker/healthcheck.py). This is a local dev / integration-test
# image, not a hardened production deployment target for an application --
# see README.md for the security caveats around clamd-over-TCP.

# --- Stage 1: build the aioclamd wheel and vendor it into an isolated dir ---
FROM python:3.12-slim AS builder

WORKDIR /src
COPY pyproject.toml README.md CHANGELOG.md LICENSE ./
COPY aioclamd ./aioclamd

# aioclamd has zero runtime dependencies (stdlib only); --no-deps keeps that
# true on purpose -- a future accidental dependency should fail loudly here.
RUN pip install --no-cache-dir build \
    && python -m build --wheel \
    && pip install --no-cache-dir --no-deps --target /opt/aioclamd-site dist/*.whl

# --- Stage 2: official ClamAV image + the packaged aioclamd client ---
#
# Pinned to a specific patch tag rather than a floating `latest`/`stable` tag
# to avoid silent drift. Refresh periodically (e.g. via Dependabot's docker
# ecosystem, or Renovate). To pin by digest instead of tag, resolve it with:
#   docker pull clamav/clamav:1.5.4-debian13-slim
#   docker inspect --format='{{index .RepoDigests 0}}' clamav/clamav:1.5.4-debian13-slim
FROM clamav/clamav:1.5.4-debian13-slim

# python3 only -- no pip/build tooling ships in the final image.
RUN apt-get update \
    && apt-get install --no-install-recommends -y python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/aioclamd-site /opt/aioclamd-site
ENV PYTHONPATH=/opt/aioclamd-site

COPY docker/healthcheck.py /usr/local/bin/healthcheck.py

# The base image's own env-var config mechanism (CLAMD_CONF_*) is only
# processed by the privileged entrypoint (/init); since we run unprivileged
# (/init-unprivileged, see below), patch clamd.conf directly at build time
# instead, using the same sed idiom the upstream Dockerfile itself uses to
# set keys regardless of whether they're currently commented out.
#
# aioclamd's instream() enforces no client-side cap on stream size of its
# own (see security review) -- this is the real backstop. 100M is a starting
# default; tune it to your workload and risk tolerance.
# Anchored at line-start (with an optional leading '#') so this only ever
# matches the real keys -- an unanchored pattern would also clobber unrelated
# keys that merely contain these as a substring (e.g. OnAccessMaxFileSize).
RUN sed -i \
      -e 's|^#\?\(StreamMaxLength\) .*|\1 100M|' \
      -e 's|^#\?\(MaxFileSize\) .*|\1 100M|' \
      -e 's|^#\?\(MaxScanSize\) .*|\1 100M|' \
      /etc/clamav/clamd.conf

# Milter is already off by default in the base image; set explicitly for
# clarity since we don't use it here.
ENV CLAMAV_NO_MILTERD=true \
    CLAMAV_NO_CLAMD=false \
    CLAMAV_NO_FRESHCLAMD=false

EXPOSE 3310

# Overrides the base image's built-in clamdcheck.sh healthcheck with one that
# exercises the actual client library (aioclamd) end-to-end, not just clamd
# in isolation. Long start-period matches upstream guidance: first boot has
# to download the full signature database via freshclam.
HEALTHCHECK --interval=30s --timeout=6s --start-period=6m --retries=3 \
    CMD ["python3", "/usr/local/bin/healthcheck.py"]

# Run clamd unprivileged, matching the base image's own documented non-root
# story. Never run this container as root in anything but local dev.
USER clamav
ENTRYPOINT ["/init-unprivileged"]
