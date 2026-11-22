# Built-in pack fixtures

Responses the built-in signature pack (`internal/detect/pack/*.yaml`) is tested against. One directory per
captured instance: `<product>/`, or `<product>-<variant>/` when one product has several (for example
`wordpress/` for `wordpress:latest` and `wordpress-4.7/` for a fresh `wordpress:4.7` install).

The harness in `internal/detect/pack_test.go` (`runPackFixture`) turns a directory into the fetcher and
`probe.HTTP` the scanner would see and runs `Pack()` plus the built-in rules through `Set.detect`.
`TestPackFixturesLoad` parses every directory here.

## Files in a directory

| File | Content |
|---|---|
| `root.http` | required: the raw response to `GET /` |
| `<path>.http` | the raw response to `GET <path>` for a pack path other than `/`: the path without its leading `/`, every further `/` written as `__` (`/api/version` -> `api__version.http`) |
| `favicon.ico` | optional: the raw bytes of `/favicon.ico` when it answered 200; the harness computes its SHA-256 and mmh3 |
| `source.txt` | where the fixture comes from: for a capture the image (`wordpress:4.7`), the lab-agh compose file and the capture date; for a written fixture `documented markers` and the documentation it follows |

A path with no `.http` file behaves like a failed request (the signature on it is not evaluated), so a capture from a
running stack should include every pack path, even when it answered 404.

## Raw response format

The output of `curl -sS -i -L --max-redirs 5 http://<host>:<port><path>` (HTTP/1.1 or HTTP/2 status lines, `\r\n` or
`\n`). Every `3xx` response with a `Location` header that is followed by another status line is a redirect hop: the
harness records its resolved location in the redirect chain and uses the last response, whose body is the rest of the
file. Headers are stored as captured; `Set-Cookie` becomes the cookie list as the prober builds it. Do not keep
secrets (session ids may stay, they are worthless after the capture) and keep bodies short where the markers allow.
