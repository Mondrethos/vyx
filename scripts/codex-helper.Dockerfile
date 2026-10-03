FROM docker.io/library/rust:1.95.0-bookworm
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
       musl-tools cmake clang libclang-dev pkg-config perl make git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && case "$(uname -m)" in \
         x86_64) rustup target add x86_64-unknown-linux-musl ;; \
         aarch64) rustup target add aarch64-unknown-linux-musl ;; \
         *) exit 1 ;; \
       esac
ENV RUSTUP_HOME=/usr/local/rustup
