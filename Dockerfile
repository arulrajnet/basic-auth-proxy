# Docker multi-stage build
# Set the BUILDPLATFORM as linux/amd64 and get the TARGETPLATFORM from build args
FROM --platform=linux/amd64 golang:1.24.0-bookworm AS base

ARG GIT_COMMIT=unspecified
ARG BUILD_IMAGE_ID=unspecified
ARG VERSION=unspecified
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ENV GIT_COMMIT=${GIT_COMMIT}
ENV BUILD_IMAGE_ID=${BUILD_IMAGE_ID}
ENV VERSION=${VERSION}

WORKDIR /app

# Fetch dependencies
COPY go.mod go.sum ./
RUN go mod download

# Now pull in our code
COPY . .

# Set the cross compilation arguments based on the TARGETPLATFORM which is
# automatically set by the docker engine.
RUN case ${TARGETPLATFORM} in \
        "windows/amd64") GOOS=windows GOARCH=amd64 ;; \
        "linux/amd64") GOOS=linux GOARCH=amd64  ;; \
        # arm64 and arm64v8 are equivalent in go and do not require a goarm
        # https://github.com/golang/go/wiki/GoArm
        "linux/arm64" | "linux/arm/v8") GOOS=linux GOARCH=arm64  ;; \
        "linux/ppc64le") GOOS=linux GOARCH=ppc64le  ;; \
        "linux/s390x") GOOS=linux GOARCH=s390x  ;; \
        "linux/riscv64") GOOS=linux GOARCH=riscv64  ;; \
        "linux/arm/v5") GOOS=linux GOARCH=arm GOARM=5  ;; \
        "linux/arm/v6") GOOS=linux GOARCH=arm GOARM=6  ;; \
        "linux/arm/v7") GOOS=linux GOARCH=arm GOARM=7 ;; \
        "linux/386") GOOS=linux GOARCH=386  ;; \
        "windows/386") GOOS=windows GOARCH=386  ;; \
    esac && \
    printf "Building basic-auth-proxy for OS: ${GOOS}, Arch: ${GOARCH}\n" && \
    GOOS=${GOOS} GOARCH=${GOARCH} VERSION=${VERSION} make build_binary

# Final image
FROM scratch AS final
LABEL maintainer="Arulraj V <me@arulraj.net>"

ARG VERSION=unspecified
ENV VERSION=${VERSION}

COPY --from=base /app/dist/basic-auth-proxy /usr/bin/basic-auth-proxy

LABEL org.opencontainers.image.licenses=MIT \
      org.opencontainers.image.description="A Secure and Brandable Reverse Proxy for Upstream Services with Basic Auth." \
      org.opencontainers.image.documentation=https://arulrajnet.github.io/basic-auth-proxy/ \
      org.opencontainers.image.source=https://github.com/arulrajnet/basic-auth-proxy \
      org.opencontainers.image.url=https://hub.docker.com/repository/docker/arulrajnet/basic-auth-proxy \
      org.opencontainers.image.title=basic-auth-proxy \
      org.opencontainers.image.version=${VERSION}

CMD ["basic-auth-proxy"]
