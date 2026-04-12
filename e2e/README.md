# E2E Framework

[Project link](https://github.com/orgs/tinyauthapp/projects/1/views/1)

This is designed as an E2E framework to be able to test for changes in common proxy and application apps that tinyauth users are likely to use.

This is **not** designed to test functionality, it is a [Canary](https://en.wikipedia.org/wiki/Sentinel_species#Canaries). All functionailty testing is already done by Unit tests within the standard tinyauth PR / release workflows.

## Design

Primary testing is via Docker, although a minimal Kubernetes stack is also planned.

Initially this is being created to test the proxy connection, and ability to login.

Testing of endpoints and providers will be done via `traefik`.

It requires at least two endpoints, one will be `whoami` as an easy "is this working", but it also later requires an OIDC test (TBD), and a nested HTTP Auth (TBD).

It should test against all "known" Oauth providers (ie, the ones that are specifically mentioned in the documentation, including community supplied if possible).

> [!NOTE]
> This requires having both Google and Github logins for the built-in providers, so security for those on a public E2E setup must be taken into account.

## Running

Run the <./test.sh> script, this handles everything for all tests.

TODO: Implement options to limit testing to specific proxies and auth services.
