Version 1.0.29
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed
- change xml-kit dependency to minimum 0.3.0
- use `encrypt_data_for` instead of `encryption_for`.

## [1.0.29] - 2018-12-04
### Changed
- change xml-kit dependency to ~> 0.2.

## [1.0.28] - 2018-12-04
### Changed
- Parse attribute arrays from SAML assertion.

## [1.0.27] - 2018-11-08
### Changed
- Evict expired key pairs from configuration.

## [1.0.26] - 2018-10-22
### Changed
- Forward destination, issuer, now, embed\_signature to assertion.

## [1.0.25] - 2018-10-17
### Changed
- Allow multi valued attributes in response assertion.

## [1.0.24] - 2018-09-18
### Added
- Parse ID from assertion.
- Parse version from assertion.
- Parse version from assertion.
- Add missing English translations.

### Changed
- Moved backing fields from response builder to assertion.

## [1.0.23] - 2018-08-23
### Added
- Add NotOnOrAfter attribute to SubjectConfirmationData.

## [1.0.22] - 2018-08-13
### Added
- Allow using a custom NameID Format in Assertion.

## [1.0.21] - 2018-08-13
### Changed
- Use net/hippie instead of net/http.

### Removed
- remove optional NotOnOrAfter attribute from SubjectConfirmationData.

## [1.0.20] - 2018-08-11
### Changed
- Synchronize NotOnOrAfter between AuthnStatement and SubjectConfirmationData.

### Removed
- Removed optional SessionNotOnOrAfter attribute from AuthnStatement.

[Unreleased]: https://github.com/saml-kit/saml-kit/compare/v1.0.29...HEAD
[1.0.29]: https://github.com/saml-kit/saml-kit/compare/v1.0.28...v1.0.29
[1.0.28]: https://github.com/saml-kit/saml-kit/compare/v1.0.27...v1.0.28
[1.0.27]: https://github.com/saml-kit/saml-kit/compare/v1.0.26...v1.0.27
[1.0.26]: https://github.com/saml-kit/saml-kit/compare/v1.0.25...v1.0.26
[1.0.25]: https://github.com/saml-kit/saml-kit/compare/v1.0.24...v1.0.25
[1.0.24]: https://github.com/saml-kit/saml-kit/compare/v1.0.23...v1.0.24
[1.0.23]: https://github.com/saml-kit/saml-kit/compare/v1.0.22...v1.0.23
[1.0.22]: https://github.com/saml-kit/saml-kit/compare/v1.0.21...v1.0.22
[1.0.21]: https://github.com/saml-kit/saml-kit/compare/v1.0.20...v1.0.21
[1.0.20]: https://github.com/saml-kit/saml-kit/compare/v1.0.19...v1.0.20
[1.0.19]: https://github.com/saml-kit/saml-kit/compare/v1.0.18...v1.0.19
[1.0.18]: https://github.com/saml-kit/saml-kit/compare/v1.0.17...v1.0.18
[1.0.17]: https://github.com/saml-kit/saml-kit/compare/v1.0.16...v1.0.17
[1.0.16]: https://github.com/saml-kit/saml-kit/compare/v1.0.15...v1.0.16
[1.0.15]: https://github.com/saml-kit/saml-kit/compare/v1.0.14...v1.0.15
[1.0.14]: https://github.com/saml-kit/saml-kit/compare/v1.0.13...v1.0.14
[1.0.13]: https://github.com/saml-kit/saml-kit/compare/v1.0.12...v1.0.13
[1.0.12]: https://github.com/saml-kit/saml-kit/compare/v1.0.11...v1.0.12
[1.0.11]: https://github.com/saml-kit/saml-kit/compare/v1.0.10...v1.0.11
[1.0.10]: https://github.com/saml-kit/saml-kit/compare/v1.0.9...v1.0.10
[1.0.9]: https://github.com/saml-kit/saml-kit/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/saml-kit/saml-kit/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/saml-kit/saml-kit/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/saml-kit/saml-kit/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/saml-kit/saml-kit/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/saml-kit/saml-kit/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/saml-kit/saml-kit/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/saml-kit/saml-kit/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/saml-kit/saml-kit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/saml-kit/saml-kit/compare/v0.3.6...v1.0.0
[0.3.6]: https://github.com/saml-kit/saml-kit/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/saml-kit/saml-kit/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/saml-kit/saml-kit/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/saml-kit/saml-kit/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/saml-kit/saml-kit/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/saml-kit/saml-kit/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/saml-kit/saml-kit/compare/v0.2.18...v0.3.0
[0.2.18]: https://github.com/saml-kit/saml-kit/compare/v0.2.17...v0.2.18
[0.2.17]: https://github.com/saml-kit/saml-kit/compare/v0.2.16...v0.2.17
[0.2.16]: https://github.com/saml-kit/saml-kit/compare/v0.2.15...v0.2.16
[0.2.15]: https://github.com/saml-kit/saml-kit/compare/v0.2.14...v0.2.15
[0.2.14]: https://github.com/saml-kit/saml-kit/compare/v0.2.13...v0.2.14
[0.2.13]: https://github.com/saml-kit/saml-kit/compare/v0.2.12...v0.2.13
[0.2.12]: https://github.com/saml-kit/saml-kit/compare/v0.2.11...v0.2.12
[0.2.11]: https://github.com/saml-kit/saml-kit/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/saml-kit/saml-kit/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/saml-kit/saml-kit/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/saml-kit/saml-kit/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/saml-kit/saml-kit/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/saml-kit/saml-kit/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/saml-kit/saml-kit/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/saml-kit/saml-kit/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/saml-kit/saml-kit/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/saml-kit/saml-kit/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/saml-kit/saml-kit/compare/v0.1.0...v0.2.1
