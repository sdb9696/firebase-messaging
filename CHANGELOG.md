# Changelog

## [0.4.4](https://github.com/sdb9696/firebase-messaging/tree/0.4.4) (2024-09-27)

[Full Changelog](https://github.com/sdb9696/firebase-messaging/compare/0.4.3...0.4.4)

**Release highlights:**

- Revert changes to compiled protobuf files so they are back to 4.24 to avoid ongoing release management headaches.

**Merged pull requests:**

- Revert protobuf compilation changes [\#19](https://github.com/sdb9696/firebase-messaging/pull/19) (@sdb9696)

## [0.4.3](https://github.com/sdb9696/firebase-messaging/tree/0.4.3) (2024-09-25)

[Full Changelog](https://github.com/sdb9696/firebase-messaging/compare/0.4.2...0.4.3)

**Release highlights:**

- Suppress unnecessary warnings from dependent library.

**Fixed bugs:**

- Catch excessive protobuf warnings [\#16](https://github.com/sdb9696/firebase-messaging/pull/16) (@sdb9696)

## [0.4.2](https://github.com/sdb9696/firebase-messaging/tree/0.4.2) (2024-09-25)

[Full Changelog](https://github.com/sdb9696/firebase-messaging/compare/0.4.1...0.4.2)

**Release highlights:**

Upgrades protobuf dependency to 5.28.

**Project maintenance:**

- Fix publish workflow to testpypi [\#15](https://github.com/sdb9696/firebase-messaging/pull/15) (@sdb9696)
- Update protobuf to 5.28 [\#12](https://github.com/sdb9696/firebase-messaging/pull/12) (@sdb9696)

## [0.4.1](https://github.com/sdb9696/firebase-messaging/tree/0.4.1) (2024-09-06)

[Full Changelog](https://github.com/sdb9696/firebase-messaging/compare/0.4.0...0.4.1)

**Release highlights:**

Migration to uv for project/package management

**Project maintenance:**

- Migrate from poetry to uv and enable testpypi publishing [\#9](https://github.com/sdb9696/firebase-messaging/pull/9) (@sdb9696)

## [0.4.0](https://github.com/sdb9696/firebase-messaging/tree/0.4.0) (2024-08-29)

[Full Changelog](https://github.com/sdb9696/firebase-messaging/compare/0.3.0...0.4.0)

**Release highlights:**

- Support for new FCM HTTP v1 API
- Previous versions of this library will no longer work due firebase [deprecating the legacy APIs](https://firebase.google.com/docs/cloud-messaging/migrate-v1)
- Dropping official python 3.8 support
- **Breaking** - this version of the library only supports being run in an asyncio event loop
- **Breaking** - The api has changed, see the readme for updated details

**Breaking change pull requests:**

- Drop python 3.8 support and update CI [\#5](https://github.com/sdb9696/firebase-messaging/pull/5) (@sdb9696)

**Implemented enhancements:**

- Support FCM HTTP v1 \(async only\) [\#4](https://github.com/sdb9696/firebase-messaging/pull/4) (@sdb9696)

**Project maintenance:**

- Update releasing instructions and add changelog [\#6](https://github.com/sdb9696/firebase-messaging/pull/6) (@sdb9696)

## [0.3.0](https://github.com/sdb9696/firebase-messaging/tree/0.3.0) (2024-03-26)

[Full Changelog](https://github.com/sdb9696/firebase-messaging/compare/0.2.1...0.3.0)

**Merged pull requests:**

- Make checkin async [\#2](https://github.com/sdb9696/firebase-messaging/pull/2) (@sdb9696)

## [0.2.1](https://github.com/sdb9696/firebase-messaging/releases/tag/0.2.1) - 2024-03-19

<small>[Compare with 0.2.0](https://github.com/sdb9696/firebase-messaging/compare/0.2.0...0.2.1)</small>

### Added

- Add typing ([ae3bc88](https://github.com/sdb9696/firebase-messaging/commit/ae3bc8821c1ca16fc6da00af0f0655851f6f848f) by sdb9696).
- Add ruff pre-commit hook ([bd98a4e](https://github.com/sdb9696/firebase-messaging/commit/bd98a4eea43ab0d63112f15f2ea3e2aa6c12f7c7) by sdb9696).
- Publisher verbose ([98cd5c4](https://github.com/sdb9696/firebase-messaging/commit/98cd5c4a40b12a42fc234d61076560a21bf46666) by sdb9696).

### Fixed

- Fix publisher ([6347dc2](https://github.com/sdb9696/firebase-messaging/commit/6347dc262df7f409099807df18db3e4550316106) by sdb9696).
- Fix cryptography warning in key generation ([5d4685b](https://github.com/sdb9696/firebase-messaging/commit/5d4685b9be3b66c3bff38ae6b4049094ba116ffb) by sdb9696).
- Fix broken proto file ([1bf3625](https://github.com/sdb9696/firebase-messaging/commit/1bf36259cd508bf6a58dc9f16138294aef235068) by sdb9696).

### Merged

- Merge pull request #1 from sdb9696/add_typing ([919eb97](https://github.com/sdb9696/firebase-messaging/commit/919eb97750dc3481130056ed6a4b9f4773b8da15) by Steven B).

## [0.2.0](https://github.com/sdb9696/firebase-messaging/releases/tag/0.2.0) - 2023-10-31

<small>[Compare with 0.1.4](https://github.com/sdb9696/firebase-messaging/compare/0.1.4...0.2.0)</small>

- Bump to 0.2.0, rename entry points and add run state for stability ([e3cbfda](https://github.com/sdb9696/firebase-messaging/commit/e3cbfda2f753e11029c437ec66720d836ccc0595) by sdb9696).

### Removed

- Remove need to be created in an event loop ([87daa6b](https://github.com/sdb9696/firebase-messaging/commit/87daa6b0078ef17131c3e64519b3042c559e3630) by sdb9696).

## [0.1.4](https://github.com/sdb9696/firebase-messaging/releases/tag/0.1.4) - 2023-10-25

<small>[Compare with 0.1.3](https://github.com/sdb9696/firebase-messaging/compare/0.1.3...0.1.4)</small>

- Relax protobuf dependency for HA ([9ac0bc6](https://github.com/sdb9696/firebase-messaging/commit/9ac0bc6d8212ea9a4fb4aa6cc412e7e760414dae) by sdb9696).

## [0.1.3](https://github.com/sdb9696/firebase-messaging/releases/tag/0.1.3) - 2023-10-25

<small>[Compare with 0.1.2](https://github.com/sdb9696/firebase-messaging/compare/0.1.2...0.1.3)</small>

- Bugfix python 3.9 async lock ([c2ee681](https://github.com/sdb9696/firebase-messaging/commit/c2ee68123ee4b8d5d62060b80ed746b2ec639b29) by sdb9696).

## [0.1.2](https://github.com/sdb9696/firebase-messaging/releases/tag/0.1.2) - 2023-10-25

<small>[Compare with 0.1.1](https://github.com/sdb9696/firebase-messaging/compare/0.1.1...0.1.2)</small>

### Fixed

- Update handling of no event loop and bump version ([29f3841](https://github.com/sdb9696/firebase-messaging/commit/29f38414eba0ed5893578c382eae558a826475de) by sdb9696).

## [0.1.1](https://github.com/sdb9696/firebase-messaging/releases/tag/0.1.1) - 2023-10-23

<small>[Compare with 0.1.0](https://github.com/sdb9696/firebase-messaging/compare/0.1.0...0.1.1)</small>

### Fixed

- Fix gcm checkin with credentials ([4c51098](https://github.com/sdb9696/firebase-messaging/commit/4c5109816b0d3fa266329bb36ec6fdfb02598ca3) by sdb9696).

## [0.1.0](https://github.com/sdb9696/firebase-messaging/releases/tag/0.1.0) - 2023-10-23

<small>[Compare with first commit](https://github.com/sdb9696/firebase-messaging/compare/acf9b784788d68026d64d2f6d39a23274dbd663e...0.1.0)</small>

### Added

- Add tests and docs and refactor ([77c225c](https://github.com/sdb9696/firebase-messaging/commit/77c225c142f1173ca2746c7a07de250b7d46e610) by sdb9696).

### Fixed

- Fix publish workflow ([447d379](https://github.com/sdb9696/firebase-messaging/commit/447d37922aa2589e79b3952036ef10b02debb01a) by sdb9696).


\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
