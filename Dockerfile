FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        build-essential \
        ca-certificates \
        cmake \
        git \
        pkg-config \
        python3 \
        libjansson-dev \
        libpcre2-dev \
        libssl-dev \
        libsystemd-dev \
        libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

# Fetch FlatCC from upstream. Pinning the revision keeps the toolchain
# reproducible while allowing callers to select another upstream revision.
ARG FLATCC_REPOSITORY=https://github.com/dvidelabs/flatcc.git
ARG FLATCC_REF=29201734bf2d12713a7a1a035d31e5123aac9c93
RUN git clone "$FLATCC_REPOSITORY" /tmp/flatcc \
    && git -C /tmp/flatcc checkout --detach "$FLATCC_REF"
RUN cmake -S /tmp/flatcc -B /tmp/flatcc-build \
        -DCMAKE_BUILD_TYPE=Release \
        -DFLATCC_TEST=OFF \
        -DFLATCC_INSTALL=ON \
        -DCMAKE_INSTALL_PREFIX=/opt/flatcc \
    && cmake --build /tmp/flatcc-build --parallel \
    && cmake --install /tmp/flatcc-build \
    && mv /tmp/flatcc /opt/flatcc-src \
    && rm -rf /tmp/flatcc-build

ENV PATH="/opt/flatcc/bin:${PATH}"
WORKDIR /workspace

CMD ["make", "repo"]
