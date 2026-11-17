# The guests' kernel: Amazon Linux's microvm kernel tree with Firecracker's
# own guest config for the series, the combination Firecracker validates,
# plus arsonist.config. The result is a FROM scratch image holding /vmlinux
# (and the /config it was built with), which hosts pull like any image.
#
# The build stage runs on the build machine's own architecture and
# cross-compiles when that is not x86_64.

FROM --platform=$BUILDPLATFORM ubuntu:24.04 AS build

ARG BUILDARCH
ARG KERNEL_TAG=microvm-kernel-6.18.25-57.115.amzn2023
# Kept equal to firecracker::VERSION; a test checks.
ARG FIRECRACKER_VERSION=v1.17.0
ARG KERNEL_CONFIG=microvm-kernel-ci-x86_64-6.18.config

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bc bison build-essential ca-certificates curl dwarves flex libelf-dev \
    libssl-dev python3 xz-utils \
    $(test "$BUILDARCH" = amd64 || echo gcc-x86-64-linux-gnu binutils-x86-64-linux-gnu) && \
    rm -rf /var/lib/apt/lists/*

ENV ARCH=x86_64
WORKDIR /src

RUN curl -fsSL "https://github.com/amazonlinux/linux/archive/refs/tags/${KERNEL_TAG}.tar.gz" \
    | tar -xz --strip-components=1

RUN curl -fsSL -o base.config \
    "https://raw.githubusercontent.com/firecracker-microvm/firecracker/${FIRECRACKER_VERSION}/resources/guest_configs/${KERNEL_CONFIG}"

COPY arsonist.config /src/arsonist.config

# merge_config.sh only warns when a requested value is dropped, so check
# every setting in the fragment, "is not set" lines too, against the final
# .config.
RUN export CROSS_COMPILE=$(test "$BUILDARCH" = amd64 || echo x86_64-linux-gnu-) && \
    scripts/kconfig/merge_config.sh -m base.config arsonist.config && \
    make olddefconfig && \
    grep -E '^(CONFIG_|# CONFIG_.* is not set$)' arsonist.config >wanted && \
    missing=0 && \
    while IFS= read -r opt; do \
      grep -qxF "$opt" .config || { echo "not in the final .config: $opt" >&2; missing=1; }; \
    done <wanted && \
    test "$missing" -eq 0 && \
    make -j"$(nproc)" vmlinux

FROM scratch
COPY --from=build /src/vmlinux /vmlinux
COPY --from=build /src/.config /config
