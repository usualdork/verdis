# The Verdis container image.
#
# It carries the tool, the build toolchain the build stage needs (so a
# project can be compiled with sanitizers) and Podman, so the proof of
# concept runs inside a sandbox rather than on the runner.
#
# The image is built once and pinned by digest in releases. The tool
# never pulls an image at run time: the image has to be present and
# pinned before the run, so the supply chain stays under the maintainer's
# control.

FROM ghcr.io/usualdork/verdis/base:latest

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY action/entrypoint.py /app/entrypoint.py

# The tool is installed as root, so the console script lands in
# /usr/local/bin. The base image runs as an unprivileged user with
# HOME=/work, and pip would otherwise install into that user's home,
# where the entrypoint would not find it.
USER root
RUN HOME=/root pip install --no-cache-dir /app
USER 65534:65534

# The build and run stages work in a scratch directory. It lives under
# the workspace so the runtime can see it.
ENV VERDIS_WORK_DIR=/github/workspace/.verdis

USER 65534:65534
WORKDIR /github/workspace

# The image runs the tool. The action's own entry point is in it too,
# for a workflow that would rather run the action inside a container.
ENTRYPOINT ["verdis"]
CMD ["--help"]
