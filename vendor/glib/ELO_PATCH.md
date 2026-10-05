# Local GLib compatibility patch

Based on glib 0.18.5, required by the current GTK3/Tauri dependency graph.
`VariantStrIter::impl_get` now passes a mutable output pointer to GLib,
backporting the upstream fix for
[RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html)
([upstream change](https://github.com/gtk-rs/gtk-rs-core/pull/1343)).
Keep the upstream licenses. Remove this patch when the GTK stack permits a
compatible upgrade to an upstream fixed release. Version-based audit tools may
still flag 0.18.5; do not suppress that warning without checking this patch.

The included `Cargo.lock` pins the standalone regression-test dependencies,
including upstream dev dependencies. The release workflow copies this package
outside the workspace and runs its tests with `--locked`; installer dependencies
continue to use the repository's root lockfile.
