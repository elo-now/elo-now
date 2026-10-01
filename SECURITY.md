# Reporting a vulnerability

Report suspected vulnerabilities privately to [elonow@9bits.com](mailto:elonow@9bits.com), the publisher's existing contact address. Use the subject “elo.now security report”. Do not post an unfixed exploit or private account data in a public issue.

Include the app/server version, platform, minimal reproduction using synthetic data, expected and actual behavior, and the possible impact. Never send a recovery phrase, profile password, live access token, private history, or an unredacted memory dump. Ask for a secure transfer method if a sensitive artifact is necessary.

Reports are assessed and fixes are validated with regression tests before coordinated disclosure. No guaranteed response time or independent security certification is claimed. An App Store approval or a clean dependency scan is not a protocol audit.

See [the threat model](THREAT_MODEL.md) for limitations, including the hosting operator's access to legacy General and the distinct owner-managed version-2 boundary. Source changes do not migrate deployed Spaces. Dependencies are checked against RustSec and the npm advisory service by the repository's CI workflow; results apply to the scanned lockfiles.
