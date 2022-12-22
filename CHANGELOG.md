# bedrock-vc-verifier ChangeLog

## 14.2.0 -

### Added
- Add support for `@digitalbazaar/did-method-web`

## 14.1.0 - 2022-12-17

### Added
- Ensure verification errors, such as expired credential errors, are
  serializable.

## 14.0.0 - 2022-11-03

### Changed
- **BREAKING**: Only check challenge reuse (using verifier-based challenge
  management) when `challenge` is set in `checks`.

## 13.0.1 - 2022-10-25

### Fixed
- Update `@digitalbazaar/ed25519-signature-*` and `@digitalbazaar/vc*`
  dependencies.

## 13.0.0 - 2022-10-23

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/service-context-store@9`
  - `@bedrock/service-core@7`.
- **BREAKING**: See `@bedrock/service-core@7` for important config changes
  and new peer dependency `@bedrock/oauth2-verifier@1`.

## 12.3.0 - 2022-10-10

### Changed
- Allow json `req.body` to be more than just objects or arrays.

## 12.2.0 - 2022-09-21

### Added
- Add support for eddsa-2022 cryptosuite.
- Add support for DataIntegrityProof.

## 12.1.0 - 2022-07-17

### Added
- Add support for oauth2-authorized verifier instances.

## 12.0.0 - 2022-06-30

### Changed
- **BREAKING**: Require Node.js >=16.
- **BREAKING**: Update dependenices.
  - `@digitalbazaar/vc@4`: `expirationDate` now checked.
- **BREAKING**: Update peer dependencies.
  - `@bedrock/did-io@9`
  - `@bedrock/service-agent@6`
  - `@bedrock/service-context-store@8`
  - `@bedrock/service-core@6`
- Use `package.json` `files` field.
- Lint module.

## 11.0.0 - 2022-06-05

### Changed
- **BREAKING** Use `@digitalbazaar/vc-status-list` v4.0.  If `statusPurpose`
  in credential does not match the `statusPurpose` of status list credential,
  an error will be thrown.

## 10.0.0 - 2022-05-17

### Changed
- **BREAKING**: Use `@bedrock-service-context-store@7` to cause migration of
  old EDV context documents to the new EDV attribute version.

## 9.0.0 - 2022-05-05

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/service-agent@5`
  - `@bedrock/service-context-store@6`.
- **BREAKING**: The updated peer dependencies use a new EDV client with a
  new blind attribute version. This version is incompatible with previous
  versions and a manual migration must be performed to update all
  EDV documents to use the new blind attribute version -- or a new
  deployment is required.

## 8.0.0 - 2022-04-29

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/core@6`
  - `@bedrock/credentials-context@3`
  - `@bedrock/did-context@4`
  - `@bedrock/did-io@8`
  - `@bedrock/express@8`
  - `@bedrock/https-agent@4`
  - `@bedrock/jsonld-document-loader@3`
  - `@bedrock/mongodb@10`
  - `@bedrock/security-context@7`
  - `@bedrock/service-agent@4`
  - `@bedrock/service-context-store@5`
  - `@bedrock/service-core@5`
  - `@bedrock/validation@7`
  - `@bedrock/vc-status-list-context@3`
  - `@bedrock/vc-revocation-list-context@3`
  - `@bedrock/veres-one-context@14`.

## 7.0.0 - 2022-04-23

### Changed
- **BREAKING**: Update `@digitalbazaar/vc-status-list` and
  `@bedrock/vc-status-list-context` to v3.0.

## 6.0.0 - 2022-04-06

### Changed
- **BREAKING**: Rename package to `@bedrock/vc-verifier`.
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Remove default export.
- **BREAKING**: Require node 14.x.

## 5.2.0 - 2022-03-14

### Added
- Add missing dependencies `@digitalbazaar/webkms-client@10.0` and
  `@digitalbazaar/edv-client@13.0` in test.
- Add coverage action in github workflows.

### Removed
- Remove unused dependency `crypto-ld@6.0`.
- Remove unused dependencies `veres-one-context`, `did-veres-one`, `crypto-ld`,
  `did-context` and `bedrock-views` from test.

## 5.1.0 - 2022-03-12

### Changed
- Update dependencies:
  - `@digitalbazaar/vc-status-list@2.1`.

## 5.0.0 - 2022-03-11

### Changed
- **BREAKING**: Update peer dependencies:
  - `bedrock-service-core@3`
  - `bedrock-service-context-store@3`
  - `bedrock-did-io@6.1`.

## 4.0.0 - 2022-03-01

### Changed
- **BREAKING**: Move zcap revocations to `/zcaps/revocations` to better
  future proof.
- **BREAKING**: Require `bedrock-service-core@2`, `bedrock-service-agent@2`,
  and `bedrock-service-context-store@2` peer dependencies.

## 3.1.0 - 2022-02-23

### Added
- Add default (dev mode) `app-identity` entry for `vc-verifier` service.

## 3.0.1 - 2022-02-21

### Changed
- Use `@digitalbazaar/vc-status-list-context` and updated bedrock-vc-status-list-context.
  These dependencies have no changes other than moved package locations.

## 3.0.0 - 2022-02-20

### Changed
- **BREAKING**: Complete refactor to run on top of `bedrock-service*` modules. While
  this version has similar functionality, its APIs and implementation are a clean
  break from previous versions.

## 2.3.0 - 2022-02-15

### Changed
- Refactor documentLoader.

## 2.2.0 - 2022-02-09

### Added
- Add support for "StatusList2021Credential" status checks using
  `vc-status-list@1.0`
- Add tests.

## 2.1.0 - 2021-09-14

### Added
- Add support for unsigned VPs.

## 2.0.2 - 2021-08-23

### Changed
- Update deps to fix multicodec bugs and set `verificationSuite` for `v1` to
  `Ed25519VerificationKey2020` in config.

## 2.0.1 - 2021-05-28

### Fixed
- Fix bedrock peer dependencies.

## 2.0.0 - 2021-05-28

### Changed
- **BREAKING**: Remove `axios` and use `@digitalbazaar/http-client@1.1.0`.
  Errors surfaced from `http-client` do not have the same signature as `axios`.
- **BREAKING**: Remove `cfg.ledgerHostname` and `cfg.mode` from `config.js`.
- **BREAKING**: Use [vc-revocation-list@3](https://github.com/digitalbazaar/vc-revocation-list/blob/main/CHANGELOG.md).
  Revocation list credentials must have the same issuer value as the credential
  to be revoked.
- **BREAKING**: Use [bedrock-did-io@3.0](https://github.com/digitalbazaar/bedrock-did-io/blob/main/CHANGELOG.md).
- Replace `vc-js` with `@digitalbazaar/vc`.
- Update to support ed25519 2020 signature suite.
- Update peerDeps and testDeps.

## 1.2.0 - 2021-03-03

### Fixed

- Only verify based on `options.checks`.

## 1.1.0 - 2020-05-18

### Added

- Implement W3C CCG VC Verification HTTP API.

## 1.0.0 - 2020-02-27

### Added
  - API endpoint /vc/verify which can verify a presentation.
  - Mock API endpoint /verifiers/:verifierId/verifications/:referenceId
  - Positive tests for both endpoints.
  - Utils to serialize errors in verification reports.
