#!/bin/sh
# Official Debian 13 packages, pinned to reviewed bytes from MEGA's repository.
set -eu
case "$(dpkg --print-architecture)" in
  amd64) package=amd64/megacmd_2.6.0-2.1_amd64.deb; digest=9fb8c9a31a1c40b57fb54b2e8877988d957a8fcd09b78b3131cff28f0276fd0e;;
  arm64) package=arm64/megacmd_2.6.0-1.1_arm64.deb; digest=d5e0406c5368aecc43c96bd670098ec55b9c074a042c8dfae82b475416ddb5c9;;
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
