HashPassword.au3
================

An AutoIt UDF for hashing and verifying passwords.

Current release: `v2.0.0`

Overview
--------

`HashPassword.au3` stores new passwords in this format:

- `PBKDF2-HMAC-SHA256`
- `600000` iterations
- `16` random salt bytes
- `32` derived key bytes
- `pbkdf2-sha256$iterations$salthex$derivedkeyhex`

`_CheckPassword()` also supports the legacy `hash$salt` format used by older versions of this project.

Versioning
----------

`v2.0.0` switches the default password format from the legacy custom `SHA-512 x 256` scheme to `PBKDF2-HMAC-SHA256`.

- `v1.x`: legacy `hash$salt` output
- `v2.0.0`: PBKDF2 by default, with legacy verification kept for migration

Why PBKDF2?
-----------

For new systems, `Argon2id` is generally the better password hashing choice. This project uses `PBKDF2-HMAC-SHA256` because it is standardized, widely interoperable, and available through the Windows CNG API without requiring an additional native dependency.

Notes
-----

- Passwords are not trimmed before creating a new hash.
- Modern hashes are compared in constant time.
- Legacy hashes keep their historical behavior, including trimming leading and trailing whitespace before hashing.
- The hash format includes the algorithm and work factor to make future migrations possible.

Installation
------------

Copy `HashPassword.au3` to the directory of your script and include it:

```autoit
#include "HashPassword.au3"
```

Tested with `AutoIt 3.3.18.0`.

Usage
-----

```autoit
#include "HashPassword.au3"

Local $sPassword = InputBox("HashPassword", "Enter the password to hash", "", "*")
Local $sStoredHash = _HashPassword($sPassword)

If $sStoredHash = -1 Then
    MsgBox(16, "HashPassword", "Password hashing failed.")
    Exit
EndIf

Local $sPasswordConfirmation = InputBox("HashPassword", "Enter the password again", "", "*")
If _CheckPassword($sPasswordConfirmation, $sStoredHash) Then
    MsgBox(0, "HashPassword", "Password is correct.")
Else
    MsgBox(16, "HashPassword", "Password is not correct.")
EndIf
```

Testing
-------

The repository includes a self-contained test script at `tests/HashPassword.Test.au3`.

Run it with AutoIt:

```powershell
& 'C:\Program Files (x86)\AutoIt3\AutoIt3.exe' '.\tests\HashPassword.Test.au3'
```

Migration
---------

The repository includes a legacy migration example at `examples/HashPassword.MigrateLegacy.au3`.

Typical migration flow:

1. Verify the submitted password with `_CheckPassword()`.
2. If verification succeeds and the stored hash is still legacy, create a new hash with `_HashPassword()`.
3. Replace the legacy hash with the new one.

Minimal example:

```autoit
If _CheckPassword($sPassword, $sStoredHash) Then
    If StringLeft($sStoredHash, StringLen($HP_PASSWORD_ALGORITHM) + 1) <> $HP_PASSWORD_ALGORITHM & "$" Then
        Local $sUpgradedHash = _HashPassword($sPassword)
        ; Save $sUpgradedHash to your user record here.
    EndIf
EndIf
```

References
----------

- RFC 8018: PKCS #5 v2.1 / PBKDF2
- RFC 9106: Argon2
- NIST SP 800-63B
- NIST SP 800-132
- OWASP Password Storage Cheat Sheet
