#!/bin/sh
# Official Debian 13 packages, pinned to reviewed bytes from MEGA's repository.
set -eu
case "$(dpkg --print-architecture)" in
  amd64) package=amd64/megacmd_2.7.0-1.1_amd64.deb; digest=d8c3c77d0417cba498fa6d4b3804fb657721afed072d6472c10e6b0b1b02dab9;;
  arm64) package=arm64/megacmd_2.7.0-1.1_arm64.deb; digest=6d032193817581984a698f641a2f35703a677d5697923df9fda43f7a317d528b;;
  *) printf '%s\n' 'MEGAcmd container supports amd64 and arm64 only.' >&2; exit 1;;
esac
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  "https://mega.nz/linux/repo/Debian_13/$package" --output /tmp/megacmd.deb
printf '%s  %s\n' "$digest" /tmp/megacmd.deb | sha256sum --check --status
apt-get update
apt-get install -y --no-install-recommends /tmp/megacmd.deb
# Package installation adds an updater repository. Runtime containers never update
# themselves; package upgrades require new reviewed hashes and a rebuilt image.
rm -f /etc/apt/sources.list.d/megasync.list /tmp/megacmd.deb
rm -rf /var/lib/apt/lists/*
test -x /usr/bin/mega-cmd-server
