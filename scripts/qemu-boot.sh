#!/bin/bash
# Boot a guest the way a slot does, under QEMU instead of Firecracker, so
# the guest side (initramfs, init, mounts, the agent, Ctrl-Alt-Del, reset)
# can be tried without KVM. Runs in a container; needs Docker, and
# /dev/vhost-vsock for the guest to reach the host's ssh agent, which here
# is OpenSSH's with a key made for the run.
#
#   scripts/qemu-boot.sh <vmlinux> <static x86_64 arsonist>
#
# It boots twice on one cache disk: the first job runs to the end, the
# second is stopped with Ctrl-Alt-Del while it runs and must still finish.
set -euo pipefail

kernel=$(realpath "$1")
arsonist=$(realpath "$2")
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

docker build -q --platform linux/amd64 -t arsonist-qemu-test "$repo/scripts/qemu" >/dev/null
cid=$(docker create --platform linux/amd64 arsonist-qemu-test)
docker export "$cid" >"$work/image.tar"
docker rm "$cid" >/dev/null
cp "$kernel" "$work/vmlinux"
cp "$arsonist" "$work/arsonist"
mkdir -p "$work/hooks"
echo "export FROM_HOOK=1" >"$work/hooks/environment"

cat >"$work/inner.sh" <<'INNER'
set -euo pipefail
apt-get update -qq >/dev/null
apt-get install -y -qq qemu-system-x86 erofs-utils e2fsprogs socat openssh-client >/dev/null 2>&1
cd /work
ssh-keygen -q -t ed25519 -N '' -C qemu-test-key -f test-key
ssh-agent -a /work/agent.sock >/dev/null
SSH_AUTH_SOCK=/work/agent.sock ssh-add -q test-key
# In a subshell, so boot()'s `wait` does not wait for it.
(socat VSOCK-LISTEN:1022,fork UNIX-CONNECT:/work/agent.sock &)
mkfs.erofs --quiet --tar=f -zlz4 rootfs.erofs image.tar
ext4() { truncate -s "$2" "$1" && mkfs.ext4 -q -F -m 0 -L "$3" -E lazy_itable_init=1,lazy_journal_init=1,nodiscard "$1"; }
ext4 cache.ext4 1G arsonist-cache

boot() {
  local name=$1 wait=$2
  ext4 scratch.ext4 2G arsonist-scratch
  cat >guest.json <<JSON
{
  "hostname": "qemu-test-1",
  "dns": ["10.0.2.3"],
  "env": [["IMAGE_VAR", "overridden-by-pool"], ["POOL_VAR", "from-the-pool"], ["FAKE_AGENT_WAIT", "$wait"],
          ["BUILDKITE_AGENT_TOKEN", "not-a-token"], ["BUILDKITE_AGENT_NAME", "qemu-test-1"], ["BUILDKITE_AGENT_TAGS", "queue=test"],
          ["SSH_AUTH_SOCK", "/run/arsonist/ssh-agent.sock"]],
  "agent": ["buildkite-agent", "start", "--disconnect-after-job", "--tags-from-host", "--no-pty"],
  "cache_paths": ["/buildkite/builds", "/var/lib/docker"],
  "files": ["/buildkite/hooks"],
  "discard": true,
  "ssh_agent": true,
  "info": {"slot": "test-1", "host": "qemu", "image": "arsonist-qemu-test", "kernel": "local", "arsonist": "dev"}
}
JSON
  cargo run -q --manifest-path /src/Cargo.toml --example initramfs -- /work/arsonist guest.json initrd.cpio /work/hooks
  rm -f mon.sock "$name.log"
  if [ "$wait" = 1 ]; then
    ( until grep -q "waiting for SIGTERM" "$name.log" 2>/dev/null; do sleep 1; done
      echo "sendkey ctrl-alt-delete" | socat - UNIX-CONNECT:mon.sock >/dev/null
      echo "--- sent Ctrl-Alt-Del ---" ) &
  fi
  timeout 600 qemu-system-x86_64 -M pc -cpu max -m 2048 -smp 2 -no-reboot -nodefaults \
    -display none -serial stdio -monitor unix:mon.sock,server,nowait \
    -kernel vmlinux -initrd initrd.cpio \
    -append "console=ttyS0 reboot=k panic=1 ip=10.0.2.15::10.0.2.2:255.255.255.0:qemu-test-1:eth0:off:10.0.2.3 quiet" \
    -drive file=rootfs.erofs,format=raw,if=virtio,readonly=on \
    -drive file=scratch.ext4,format=raw,if=virtio \
    -drive file=cache.ext4,format=raw,if=virtio \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -device virtio-rng-pci -device vhost-vsock-pci,guest-cid=3 </dev/null 2>&1 | tee "$name.log"
  echo "--- $name: QEMU exited ${PIPESTATUS[0]} ---"
  wait
}

boot first 0
boot stopped 1
e2fsck -fn cache.ext4 >/dev/null && echo "--- cache disk is clean ---"
grep -q "ssh agent at .*: 256 SHA256:.* qemu-test-key" first.log &&
  echo "--- the guest reached the host's ssh agent ---"
INNER

# Docker's seccomp profile refuses AF_VSOCK sockets, which the agent's
# listener needs.
docker run --rm --device /dev/vhost-vsock --security-opt seccomp=unconfined \
  -v "$repo:/src" -v "$work:/work" \
  -v arsonist-target:/target -v arsonist-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target -w /src rust:1 bash /work/inner.sh
