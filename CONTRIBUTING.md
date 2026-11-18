# Contributing

## Building

Building requires Go 1.26.4 or later (see [go.mod](go.mod)); CI uses Go 1.27.

`make build` builds `bin/keysync`.

## Formatting/checking

`make check` runs the same checks as CI: `go mod tidy`, formatting, the
copyright check, `gosec`, `golangci-lint`, the build and the unit tests. It
requires:

- gosec v2.30.0
- golangci-lint v2.15.0, configured in [.golangci.yml](.golangci.yml)

These are the versions used in CI (see the
[workflow](.github/workflows/go-k8s-enc-image-operator.yaml)), which Renovate
keeps up to date.

Every Go file needs the license header, and the copyright year of changed
files has to be the current one: `make copyright` updates both. Changed files
are those differing from `origin/master`, so the check needs a remote named
`origin` pointing to this repository (not a fork whose `master` is behind).

## End-to-end tests

See [End-to-end tests](README.md#end-to-end-tests) in the README.
