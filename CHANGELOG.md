
# 0.2.3
1. Reimplemented self signing local authentication through LocalClient.
2. Added Validator method to OidcSigner.
3. Cleaned up tests so critical ones pass.

# 0.2.2
1. Removed support for self signing
2. Implemented proper state verification
3. Refactored to allow for multiple OIDC endpoints + clients.
4. Allowed configs to reflect supplying human readable names for OIDC discovery endpoints.
5. Adding a means for tracking post login redirect route as a query parameter
6. Modified request routes for login to allow specific ISS redirect.
7. Switched configuration to use `secret_ref` for file:///absolute/path, https://, and env:// for supplying client secret.
8. Setup to use refresh tokens properly (to re-request access tokens and store as cookies).

# 0.2.1
1. Refactor so OIDCConfig uses a path to secret rather than storing the secret itself.
2. Refactor to make code more modular.
3. Added support for token exchange.
4. Fixed token expiration issue.
5. Refactor to allow for multiple identity providers in configs.