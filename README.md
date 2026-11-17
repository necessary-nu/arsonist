# arsonist

Buildkite agents in single-use Firecracker microVMs, booted straight from
OCI images.

A host runs a fixed set of **slots**. A slot boots a microVM, the VM's agent
takes one job (`--disconnect-after-job`), and when the job is done the VM is
thrown away and the slot boots a new one. Every job starts from a clean root
filesystem, gets its own kernel, and can run a real `dockerd`. No Docker,
sysbox or privileged containers on the host.

It is one static binary. On the host it converts images, sets up the
network and runs the slots under systemd; inside each VM the same binary is
init.

## How it works

```
image (any OCI/Docker image with buildkite-agent on its PATH)
  │  arsonist images update: resolve tag → linux/amd64 digest, download the
  │  layers, flatten them, stream through mkfs.erofs
  ▼
/var/lib/arsonist/images/<ref>/<digest>/rootfs.erofs      ← current symlink
/var/lib/arsonist/kernel/<digest>/vmlinux                 ← current symlink

arsonist@<slot>.service ── per boot ─┬─ initrd.cpio: arsonist as /init, plus this
                                     │  boot's config, token and shared files
                                     ├─ rootfs.erofs (hard link, read-only)
                                     ├─ scratch.ext4 (new, empty)
                                     ├─ cache.ext4 (the slot's, kept)
                                     └─ jailer ─▶ firecracker ─▶ guest
```

**Images** are ordinary container images. The host checks each pool's tag
every five minutes. A new digest is downloaded and its layers flattened the
way overlayfs would stack them, whiteouts and opaque directories included,
then streamed into `mkfs.erofs`. The image config's `Env` is kept, as Docker
would have set it. An image with no `buildkite-agent` on its `PATH` is
refused before it can reach a slot.

**Every boot** gets a fresh initramfs holding this binary as `/init` and a
JSON config: the agent's token, name and tags, the image's environment, the
cache paths, and copies of the host files listed under `[[files]]` (hooks,
secrets). Secrets live in the guest's memory, nowhere on its disks. Nothing
in the image has to know about arsonist.

**In the guest**, init finds the drives by superblock (the one erofs, and
ext4 labels `arsonist-scratch` and `arsonist-cache`), puts the image under an
overlay whose upper layer is the scratch disk, and switches into it. It
mounts what a container runtime would, binds each `cache.paths` entry from
the cache disk, binds the shared files, starts `dockerd` if the image has
it, and runs `buildkite-agent start --disconnect-after-job`. When the agent
exits, init stops everything, puts the cache disk away cleanly and resets
the VM. Firecracker exits and the slot boots the next VM.

**The kernel** is Amazon Linux's `microvm-kernel-*` tree built with
Firecracker's own guest config for that series, which is the combination
Firecracker validates, plus [`kernel/arsonist.config`](kernel/arsonist.config).
CI publishes it as `ghcr.io/necessary-nu/arsonist-kernel:latest`, a private
package, and hosts pull it like any image.

**Networking**: slot _n_ gets a tap `arsonist<n>` and the _n_th /30 of
`network.subnet`. The kernel configures the guest from `ip=`, so the guest
runs no DHCP. The host NATs the guests out; guests cannot reach each other
or open connections to the host.

**Isolation**: Firecracker runs under its jailer, chrooted, as its own uid
per slot (`uid_base + n`), inside the slot unit's cgroup. A VM's memory and
CPUs are bounded by its size.

## Stopping and rolling out

There is nothing to drain. Each slot boots its next VM from whatever
`current` points at once its job ends, and a running VM keeps the image it
booted from, since its jail holds hard links to it.

`systemctl stop arsonist@linux-1` asks the guest to stop with Ctrl-Alt-Del.
Init passes one SIGTERM to the agent, which finishes its job and exits; then
the VM resets and the slot stops. A second stop signal kills the VM.

Upgrading arsonist itself works the same way: replace the binary, and each
slot restarts into the new one between jobs.

By default a slot's cache disk starts over when its pool's image changes.
It also starts over when it is more than `cache.reset_usage` full at boot,
when its configured size changes, or when `e2fsck` cannot repair it.

To hold a pool on a known-good image, pin its digest:
`image = "ghcr.io/divvun/divvun-actions:ubuntu-latest@sha256:…"`.

## Setting up a host

Requirements: x86_64 with `/dev/kvm`, systemd with cgroup v2, and apt for
the automatic package install (Ubuntu 24.04 is what this targets).

The repository and the kernel package are private. Each host needs a
GitHub token that can read packages (`read:packages`) in both necessary-nu,
for the kernel, and the organisations whose images the pools boot.

```sh
gh release download --repo necessary-nu/arsonist --pattern arsonist-x86_64-linux
sudo install -m 755 arsonist-x86_64-linux /usr/local/bin/arsonist
sudo arsonist setup          # e2fsprogs, erofs-utils, iproute2, nftables; pinned Firecracker; example config
sudoedit /etc/arsonist/config.toml
echo -n "$BUILDKITE_AGENT_TOKEN" | sudo install -m 600 /dev/stdin /etc/arsonist/agent-token
echo -n "$GHCR_TOKEN" | sudo arsonist auth login ghcr.io -u <github user>
sudo arsonist install        # systemd units, one arsonist@<slot> per slot
sudo arsonist status
```

`install` is idempotent. Run it again after editing the config: it enables
new slots, and stops removed ones once their jobs finish.

If Docker also runs on the host, its FORWARD policy is handled through the
`DOCKER-USER` chain. Any other default-drop FORWARD policy (ufw) has to
allow `arsonist+`.

## Operating

|                                |                                                    |
| ------------------------------ | -------------------------------------------------- |
| Logs (agent and guest console) | `journalctl -u arsonist@linux-1 -f`                |
| Image conversions              | `journalctl -u arsonist-images`                    |
| Convert now                    | `sudo systemctl start arsonist-images`             |
| Stop a slot after its job      | `sudo systemctl stop arsonist@linux-1`             |
| Stop it now, killing the job   | `sudo systemctl kill -s SIGKILL arsonist@linux-1`  |
| Empty a slot's cache           | `sudo arsonist slot reset-cache linux-1`           |
| See what a guest would get     | `arsonist images export <image> -o rootfs.tar`     |
| See the whole kernel boot      | `[kernel] args = ""`, then restart the slot        |

A guest that cannot start (a broken image, `dockerd` not coming up, the
agent failing to register) waits 60 seconds before it resets, so a bad
release shows up as slots repeatedly logging the failure, not as a tight
boot loop. The host backs off the same way when Firecracker itself fails.

Jobs can read `/run/arsonist/vm.json` for the slot, host, image digest and
kernel digest they run on.

## Developing

arsonist builds and runs on Linux only. On a Mac, test in a container and
cross-build:

```sh
docker run --rm -v "$PWD:/src" -w /src rust:1 cargo test
cargo zigbuild --release --target x86_64-unknown-linux-musl
docker buildx build --platform linux/amd64 --output type=local,dest=out kernel/
scripts/qemu-boot.sh out/vmlinux target/x86_64-unknown-linux-musl/release/arsonist
```

`scripts/qemu-boot.sh` boots a guest the way a slot does, but under QEMU
with no KVM needed, against a stand-in image whose `buildkite-agent` reports
what it finds. It boots twice on one cache disk. The first job runs to the
end; the second is stopped with Ctrl-Alt-Del and must still finish.

The binary must be static: the initramfs holds nothing else, so the guest
has no libc to load. `arsonist slot run` refuses a dynamically linked build.
