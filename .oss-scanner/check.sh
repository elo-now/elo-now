#!/bin/sh
# Run inside the scanner image with Docker networking disabled.
set -eu
cd /src

cargo test --locked --offline \
    -p elo-core -p elo-cli -p elo-team -p elo-witness -p elo-storage \
    -p elo-wake -p elo-call-service
cargo test --locked --offline -p elo-core --example witnessed_space_qa

# Match the headless native-client suites used by the ordinary desktop CI.
for suite in hosting::tests push:: result_metadata_tests:: release_policy::tests:: \
    diagnostics:: native_session:: incoming_calls:: native_media:: foreground_ringtone::
do
    cargo test --locked --offline -p elo-desktop --lib "$suite"
done

npm --prefix apps/desktop run build
npm --prefix apps/desktop test
python3 -m unittest discover -s tests -v
for directory in hosting storage containers admin diagnostics
do
    python3 -m unittest discover -s "deploy/$directory" -v
done
