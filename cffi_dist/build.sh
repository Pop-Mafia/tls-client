#!/bin/sh

# This build.sh file was created on a OSX host system. If you are running on windows / unix you need to adjust the commands accordingly.
VERSION="${1:-dev}"   # allow: ./build.sh 1.10.3

echo 'Build OSX'
GOOS=darwin CGO_ENABLED=1 GOARCH=arm64 go build -buildmode=c-shared -o ./dist/tls-client-darwin-arm64-$VERSION.dylib
GOOS=darwin CGO_ENABLED=1 GOARCH=amd64 go build -buildmode=c-shared -o ./dist/tls-client-darwin-amd64-$VERSION.dylib

echo 'Build Linux ARM64'
# CC is needed when you cross compile from OSX to Linux
# On Macos:
GOOS=linux CGO_ENABLED=1 GOARCH=arm64 CC="aarch64-unknown-linux-gnu-gcc" go build -buildmode=c-shared -o ./dist/tls-client-linux-arm64-$VERSION.so

# On Linux:
#GOOS=linux CGO_ENABLED=1 GOARCH=arm64 CC="aarch64-linux-gnu-gcc" go build -buildmode=c-shared -o ./dist/tls-client-linux-arm64-$VERSION.so

echo 'Build Linux ARMv7'
# CC is needed when you cross compile from OSX to Linux
GOOS=linux CGO_ENABLED=1 GOARCH=arm CC="armv7-linux-gnueabihf-gcc" go build -buildmode=c-shared -o ./dist/tls-client-linux-armv7-$VERSION.so

# CC is needed when you cross compile from OSX to Linux
echo 'Build Linux Alpine'
# For some reason my OSX gcc cross compiler does not work. Therefore i use a alpine docker image
# GOOS=linux CGO_ENABLED=1 GOARCH=amd64 CC="x86_64-linux-musl-gcc" go build -buildmode=c-shared -o ./dist/tls-client-linux-amd64.so
# Make sure to first build the image based on the Dockerfile.alpine.compile in this directory.
docker run --rm \
  -v "$PWD/../:/tls-client" \
  tls-client-alpine-go-1.24 \
  bash -c '
    cd /tls-client/cffi_dist
    GOOS=linux CGO_ENABLED=1 GOARCH=amd64 \
      go build -buildvcs=false -buildmode=c-shared \
      -o dist/tls-client-linux-alpine-amd64-'"$VERSION"'.so
  '

# CC is needed when you cross compile from OSX to Linux
echo 'Build Linux Ubuntu'
# For some reason my OSX gcc cross compiler does not work. Therefore i use a ubuntu docker image
# GOOS=linux CGO_ENABLED=1 GOARCH=amd64 CC="x86_64-linux-musl-gcc" go build -buildmode=c-shared -o ./dist/tls-client-linux-amd64.so
# Make sure to first build the image based on the Dockerfile.ubuntu.compile in this directory.
docker run --rm \
  -v "$PWD/../:/tls-client" \
  tls-client-ubuntu-go-1.24 \
  bash -c '
    cd /tls-client/cffi_dist
    GOOS=linux CGO_ENABLED=1 GOARCH=amd64 \
      go build -buildvcs=false -buildmode=c-shared \
      -o dist/tls-client-linux-ubuntu-amd64-'"$VERSION"'.so
  '

# CC is needed when you cross compile from OSX to Windows
echo 'Build Windows 32 Bit'
GOOS=windows CGO_ENABLED=1 GOARCH=386 CC="i686-w64-mingw32-gcc" go build -buildmode=c-shared -o ./dist/tls-client-windows-32-$VERSION.dll

# CC is needed when you cross compile from OSX to Windows
echo 'Build Windows 64 Bit'
GOOS=windows CGO_ENABLED=1 GOARCH=amd64 CC="x86_64-w64-mingw32-gcc" go build -buildmode=c-shared -o ./dist/tls-client-windows-64-$VERSION.dll

echo 'Build with xgo'
xgo -buildmode=c-shared -out dist/tls-client-xgo-$VERSION .