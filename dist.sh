#!/usr/bin/env bash

set -o errexit
# set -x

BASH_DIR=$(dirname $(realpath "${BASH_SOURCE}"))
BINARY=${BINARY:-basic-auth-proxy}
VERSION=${VERSION:-$(git describe --tags --always --dirty)}
RELEASE_DIR="${BASH_DIR}/release"

if [[ -z ${BINARY} ]] || [[ -z ${VERSION} ]]; then
  echo "Missing required env var: BINARY=X VERSION=X $(basename $0)"
  exit 1
fi

ARCHS=(
  darwin-amd64
  darwin-arm64
  linux-amd64
  linux-arm64
  linux-armv5
  linux-armv6
  linux-armv7
  linux-ppc64le
  linux-s390x
  linux-riscv64
  freebsd-amd64
  windows-amd64
  linux-386
  windows-386
)

rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}"

# Create architecture specific release dirs
for ARCH in "${ARCHS[@]}"; do
  mkdir -p "${RELEASE_DIR}/${BINARY}-${VERSION}.${ARCH}"

  GO_OS=$(echo $ARCH | awk -F- '{print $1}')
  GO_ARCH=$(echo $ARCH | awk -F- '{print $2}')

  # Create architecture specific binaries
  if [[ ${GO_ARCH} == armv* ]]; then
    GO_ARM=$(echo $GO_ARCH | awk -Fv '{print $2}')
    GOOS=${GO_OS} GOARCH=arm GOARM=${GO_ARM} CGO_ENABLED=0 go build \
      -ldflags="-X github.com/arulrajnet/basic-auth-proxy/pkg/version.VERSION=${VERSION}" \
      -o "${RELEASE_DIR}/${BINARY}-${VERSION}.${ARCH}/${BINARY}" "${BASH_DIR}/main.go"
  else
    GOOS=${GO_OS} GOARCH=${GO_ARCH} CGO_ENABLED=0 go build \
      -ldflags="-X github.com/arulrajnet/basic-auth-proxy/pkg/version.VERSION=${VERSION}" \
      -o "${RELEASE_DIR}/${BINARY}-${VERSION}.${ARCH}/${BINARY}" "${BASH_DIR}/main.go"
  fi

  # Stay in the script directory and use absolute paths
  pushd "${RELEASE_DIR}" > /dev/null

  # Create tar file for architecture specific binary
  tar -czvf ${BINARY}-${VERSION}.${ARCH}.tar.gz ${BINARY}-${VERSION}.${ARCH}

  # Create sha256sum for architecture-specific tar
  sha256sum ${BINARY}-${VERSION}.${ARCH}.tar.gz > ${BINARY}-${VERSION}.${ARCH}.tar.gz-sha256sum.txt

  # Create sha256sum for architecture specific binary
  sha256sum ${BINARY}-${VERSION}.${ARCH}/${BINARY} > ${BINARY}-${VERSION}.${ARCH}-sha256sum.txt

  popd > /dev/null
done
