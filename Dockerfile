FROM golang:1.22.6-alpine as dev

ENV ROOT=/go/src/app
ENV CGO_ENABLED 0
WORKDIR ${ROOT}

RUN apk update
COPY go.mod go.sum ./
RUN go mod download
EXPOSE ${PORT}


FROM golang:1.22.6-alpine as builder

ENV ROOT=/go/src/app
ARG GO_ENTRYPOINT=main.go
WORKDIR ${ROOT}

RUN apk update
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o $ROOT/binary $GO_ENTRYPOINT

FROM alpine:latest as certs
RUN apk update && apk add ca-certificates

FROM busybox as prod

ENV ROOT=/go/src/app
WORKDIR ${ROOT}
COPY --from=certs /etc/ssl/certs /etc/ssl/certs
COPY --from=builder ${ROOT}/binary .

EXPOSE ${PORT}
ENTRYPOINT ["/go/src/app/binary"]