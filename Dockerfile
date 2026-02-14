# 构建参数
ARG UPSTREAM_DIGEST

FROM rust:1.93-slim AS rust-builder

WORKDIR /rust

RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release && cp target/release/license-server license-server

FROM rustdesk/rustdesk-server-pro:latest

# 添加上游镜像信息标签
ARG UPSTREAM_DIGEST
LABEL upstream.image="rustdesk/rustdesk-server-pro:latest"
LABEL upstream.digest="${UPSTREAM_DIGEST}"

COPY --from=rust-builder /rust/license-server /usr/bin/license-server

RUN chmod +x /usr/bin/license-server

RUN mkdir -p /certs && chmod 700 /certs

COPY original_ed25519.pub /certs/original_ed25519.pub

RUN cd /certs && license-server --keygen && \
    HBBS_PATH=/usr/bin/hbbs \
    HBBS_BACKUP_PATH=/usr/bin/hbbs-official \
    ORIGINAL_KEY_PATH=/certs/original_ed25519.pub \
    NEW_KEY_PATH=/certs/id_ed25519.pub \
    license-server --patch

RUN chmod 600 /certs/*

RUN ln -s /certs/ca.crt /usr/local/share/ca-certificates/rustdesk.crt && \
    update-ca-certificates

RUN chmod +x /usr/bin/hbbs

ENV LICENSE_SERVER_CRT=/certs/server.crt

ENV LICENSE_SERVER_PRIV=/certs/server.key

ENV LICENSE_SIGNKEY_PUB=/certs/id_ed25519.pub

ENV LICENSE_SIGNKEY_PRIV=/certs/id_ed25519

ENV LICENSE=UlVTVERFU0tfTElDRU5TRQ==