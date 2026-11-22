# A stand-in image for scripts/qemu-boot.sh: Alpine with a fake
# buildkite-agent that reports what the guest set up instead of running jobs.
FROM alpine:3.20
RUN apk add --no-cache openssh-client
COPY fake-buildkite-agent /usr/local/bin/buildkite-agent
ENV IMAGE_VAR=from-the-image
