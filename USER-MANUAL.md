# GoreeCloud Identity — User Manual

## Current Development use

GoreeCloud Identity is not yet an end-user authentication service. The current executable is a loopback-only Development foundation intended for engineering validation.

Run source checks with:

```bash
go test ./...
go vet ./...
go build ./cmd/goreecloud-identity
```

Running `go run ./cmd/goreecloud-identity` starts the operational service on `127.0.0.1:8860` by default and exposes only `/healthz` and `/readyz`.

## Registration policy

The current source includes a domain-level registration policy primitive. Its default is fail-closed for public registration. It does not create accounts, issue invitations, or expose registration endpoints.

No production authentication, account administration, token issuance, or Stable operation is available yet.
