/*!
# openid-examples: collection of examples for openid crate

By default all examples work with [Google OpenID Connect](https://developers.google.com/identity/protocols/oauth2/openid-connect).

You need to define two environment variables `CLIENT_ID` and `CLIENT_SECRET`.

If you want to try another OpenID provider - additionally define `ISSUER` environment variable.

## Examples

- [warp](https://github.com/kilork/openid-examples/blob/v0.8/examples/warp.rs)

```bash
export CLIENT_ID=<your google client id here>
export CLIENT_SECRET=<your google client secret>
cargo run --example=warp
```

*/

pub const INDEX_HTML: &str = include_str!("index.html");

pub mod entity;