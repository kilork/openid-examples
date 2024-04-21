# openid-examples: collection of examples for openid crate

By default all examples work with [Google OpenID Connect](https://developers.google.com/identity/protocols/oauth2/openid-connect).

You need to define two environment variables `CLIENT_ID` and `CLIENT_SECRET`.

If you want to try another OpenID provider - additionally define `ISSUER` environment variable.

To change the address where the app listens for connections, use the environment variable `LISTEN`.

The variable `REDIRECT_URL` defines the initial part of the url where we listen for connections, in general this is `http://${LISTEN}`.

## Legal

Dual-licensed under `MIT` or the [UNLICENSE](http://unlicense.org/).

## Examples

- [warp](examples/warp.rs)

```bash
export CLIENT_ID=<your google client id here>
export CLIENT_SECRET=<your google client secret>
cargo run --example=warp
```

## Development

```bash
git push -u origin `git branch --show-current`
```