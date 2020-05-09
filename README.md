# cloudflare-jwt-verify

Forward auth server to verify Cloudflare Access JWT tokens.

## Description

`cloudflare-jwt-verify` is designed to be a forward auth server to verify
[Cloudflare Access](https://www.cloudflare.com/products/cloudflare-access/)
JWT tokens.

When forwarding a user's request to your application, Cloudflare Access will include a signed JWT as a HTTP header.
This JWT needs to be authenticated to ensure the request has been signed by Cloudflare and has gone through their servers.

Documentation on how to validate the JWT can be found here
https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens/.

Using `cloudflare-jwt-verify`, you can configure your proxy instance to correctly authenticate cloudflare requests.

This image will also work if you use a split DNS, where your app is also being served to an internal network
that is not sending the Cloudflare token. Create the container with the ALLOW_LOCAL=1 environment variable and all
private IPv4 address will be allowed through.

## Example

Look into the [example](example/) directory to find an example for the traefik reverse proxy.
