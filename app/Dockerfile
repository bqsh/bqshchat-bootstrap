FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tor procps iproute2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ./init.sh /app/init.sh
RUN chmod +x /app/start.sh

COPY ./target/release/bqshchan /app/bqshchan

EXPOSE 9000

ENTRYPOINT ["/app/init.sh"]