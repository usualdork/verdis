# The base image the build and run stages use.
#
# It carries a small C/C++ toolchain with the sanitizer runtimes, so a
# project can be built with ASan and UBSan and the resulting binary can
# still run in the sandbox.
#
# The build tools are the ones a real project's build system needs:
# autotools, cmake and the compression libraries whose headers a
# project includes. Without them a release cannot be built at all, and
# the tool could not reproduce a report about it.
#
# Build it once and pin it by digest:
#
#   docker build -f docker/base.Dockerfile -t ghcr.io/usualdork/verdis/base:latest .
#   docker image inspect --format '{{.Id}}' ghcr.io/usualdork/verdis/base:latest
#
# The tool never pulls an image at run time: the image has to be present
# and pinned before the run, so the supply chain stays under the
# maintainer's control (PRD 11.4 item 5).

FROM python:3.12-slim-bookworm

ARG BUILD_ESSENTIAL=1

# The languages a report can be about. The report may name a C project, a
# Python package, a Node service or a Go program, and the tool has to be
# able to build and run all four in the same sandbox (PRD 17.1).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        llvm \
        cmake \
        make \
        autoconf \
        automake \
        libtool \
        pkg-config \
        zlib1g-dev \
        libbz2-dev \
        liblzma-dev \
        git \
        ca-certificates \
        nodejs \
        npm \
        golang-go \
    && rm -rf /var/lib/apt/lists/*

# The run stage uses the unprivileged "nobody" user (65534), which every
# Debian image already has. The workdir is a tmpfs owned by that user.
ENV HOME=/work
WORKDIR /work
USER 65534:65534

CMD ["/bin/sh"]
