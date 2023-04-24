FROM debian:bookworm as builder

RUN apt update && apt install -y clang build-essential

COPY . /cthash
WORKDIR /cthash/fuzz

RUN make

FROM debian:bookworm
COPY --from=builder /cthash/fuzz /