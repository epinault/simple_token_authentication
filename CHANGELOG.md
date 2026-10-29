## [Unreleased]

## [1.0.0] (2026-10-29)
### Changed
* First stable release. The plug API and configuration are unchanged from 0.9.1
* Repository moved to https://github.com/epinault/simple_token_authentication; package links and badges updated
* CI now tests Elixir 1.17 - 1.20 on OTP 27 - 29; Elixir 1.14 - 1.16 and OTP 25 - 26 are no longer exercised in CI
* Add a `mix precommit` alias (format, unused-lock check, compile with warnings as errors, test with coverage, credo)

### Security
* Lock `plug_crypto` 2.2.1 for development (CVE-2026-105963); consumers resolve their own `plug_crypto` and should be on >= 2.2.1

## [0.9.1] (2026-02-17)
### Fixed
* Use constant-time comparison (`Plug.Crypto.secure_compare/2`) for token lookup to prevent timing attacks

## [0.9.0] (2025-07-17)
### Changed
* Added ability to optionally add a realm to the simple auth. Allowing services to use the plug multiple times

## [0.8.0] (2024-10-01)
### Changed
* Remove support for Elixir 1.11, 1.12 and 1.13. Minimum is Elixir 1.14

## [0.7.0] (2022-11-28)
### Changed
 * Upgrade dependencies
 * Clean up some docs
 * some internal code cleaning
 * ** Breaking **  Support Elixir 1.11 and above
## [0.6.0] (2021-05-24)
### Changed
 * Upgrade dependencies
 * Adds the service name to the token identified into the conn under the key simple_token_auth_service
 * **Potentially Breaking** Depend on `persistent_term` for caching the config which requires OTP 21.2 minimum (http://erlang.org/doc/man/persistent_term.html)

## [0.5.0] (2020-07-07)
### Changed
 * Add supports for service specific token and log the service name in the metadata

For prior versions, please look at the commit log
