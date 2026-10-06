#!/bin/sh
set -eu
umask 077
ulimit -c 0
exec "$@"
