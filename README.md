# Bluebottle

Shared Go library for the Mulga stack. Bluebottle holds the cross-cutting packages that predastore, viperblock and spinifex all need, so that none of them has to depend on another service repo to get them.

## Packages

| Package | Purpose |
| --- | --- |
| `pkg/auth` | ARN parsing and formatting |
| `pkg/iampolicy` | IAM policy types, matching and evaluation |
| `pkg/masterkey` | Master key loading and derivation |
| `pkg/otelsetup` | OpenTelemetry tracer/meter/logger bootstrap, slog bridge, HTTP instrumentation, log sanitisation |
| `pkg/ratelimit` | Token bucket rate limiting and its configuration |
| `pkg/sigv4` | AWS SigV4 parsing, verification and URI canonicalisation |

## Development

```bash
make preflight   # lint + govulncheck + tests + coverage — must pass before committing
make fix         # auto-fix linter issues
make test        # unit tests
make test-race   # unit tests under the race detector
make nilaway     # advisory nil-panic analysis (not part of preflight)
```

## Licence

AGPL-3.0. See [LICENSE](LICENSE).
