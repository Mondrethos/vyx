FROM docker.io/library/rust:1.98.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release -p vyx-server \
    && mkdir /runtime-data \
    && chown 65532:65532 /runtime-data \
    && chmod 0700 /runtime-data

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /build/target/release/vyx-server /vyx-server
COPY --from=build --chown=65532:65532 /runtime-data /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/vyx-server"]
CMD ["serve", "--data-dir", "/data", "--listen", "0.0.0.0:8080"]
