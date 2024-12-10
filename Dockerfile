FROM golang:1.23.3-alpine AS builder
RUN apk --no-cache add curl unzip

WORKDIR /app

RUN curl -LO https://github.com/jeremylong/DependencyCheck/releases/download/v11.1.1/dependency-check-11.1.1-release.zip

RUN unzip dependency-check-11.1.1-release.zip
RUN rm dependency-check-11.1.1-release.zip

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/api

FROM alpine:3.18

COPY --from=builder /app/dependency-check /dependency-check
COPY --from=builder /app/main /app/main

RUN apk --no-cache add openjdk11-jre

ENV PATH="/dependency-check/bin:${PATH}"
ENV JAVA_HOME="/usr/lib/jvm/java-11-openjdk"
ENV DC_DATA_DIRECTORY="/dependency-check/data"

EXPOSE 8080

CMD ["/app/main"]

# think of a mechanism to store/refresh the cache of dependency-check