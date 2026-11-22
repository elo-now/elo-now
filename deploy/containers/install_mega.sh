#!/bin/sh
# Official Debian 13 packages, pinned to reviewed bytes from MEGA's repository.
set -eu
case "$(dpkg --print-architecture)" in
  amd64) package=amd64/megacmd_2.7.1-1.1_amd64.deb; digest=c5eac2e35031701bee220d0d95e9be87cef15d86fd525e0fadb668e11e3162bc;;
  arm64) package=arm64/megacmd_2.7.1-1.1_arm64.deb; digest=ee32a39b0e790f91de63e06ea6d7a19a415bce349c88ff6228909cc463ef9f02;;
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
