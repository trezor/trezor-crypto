# trezor-crypto

> ⚠️ **This repository is archived and no longer maintained.**
> The code has moved to the [trezor-firmware](https://github.com/trezor/trezor-firmware)
> monorepo. Do not use the historical contents of this repository.

## Where the code went

The cryptographic library previously hosted here is now developed in the
[`crypto/`](https://github.com/trezor/trezor-firmware/tree/main/crypto) directory
of the trezor-firmware monorepo, where it is actively maintained alongside the
rest of the Trezor firmware.

The source files have been removed from this repository. The last code state
here is from 2019 and is significantly out of date — many bugs and security
issues have been fixed in the monorepo since. The repository itself is kept
in place so that existing Git submodule pins and old links continue to resolve,
but **the code here must not be used**.

## Reporting security issues

**Security reports against this repository are not accepted.** Vulnerabilities
in the 2019-era code here are, with overwhelming likelihood, already fixed in
the monorepo. If you believe you have found a vulnerability in the current
Trezor cryptographic code, please report it against
[trezor-firmware](https://github.com/trezor/trezor-firmware) following its
[security policy](https://github.com/trezor/trezor-firmware/security/policy).

## Migrating

If you depend on this repository as a Git submodule or otherwise, please
re-point your dependency at the `crypto/` subtree of trezor-firmware.
