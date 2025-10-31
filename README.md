# ntfsparse

a windows credential extractor that directly reads sam, system, and security registry hives from the ntfs filesystem at the raw disk level. bypasses file locks by opening the volume handle directly and parsing the master file table (mft) to locate and extract registry hive files. implements full registry hive parsing including nk (key node) and vk (value key) structures, extracts the bootkey from system hive class names using the lsa key scrambling algorithm, derives the lsa encryption key from the bootkey using impacket-compatible methods, and decrypts both nt password hashes (using aes-128-cbc for windows 10+ or rc4-md5 for legacy) and lsa secrets (dpapi system keys, service account passwords, machine account credentials, cached domain credentials). features implementation of impacket's lsa secret decryption including lsa_secret/lsa_secret_blob structure parsing, sha256 key derivation with 1000 iterations, and aes-256/aes-128 decryption with zero-iv handling. supports both modern and legacy windows encryption schemes with raw disk parsing requiring no windows registry apis.

## build

```bash
go build -o ntfsparse.exe
```

## usage

run as administrator (required for raw disk access):

```bash
./ntfsparse.exe
```

the tool automatically:
- opens `\\.\C:` volume handle with generic_read access
- reads ntfs boot sector to locate mft
- extracts `SAM`, `SYSTEM`, and `SECURITY` hives via mft parsing
- derives bootkey from system\controlset001\control\lsa key class names
- derives lsa key from bootkey using polsecretencryptionkey (impacket-compatible)
- decrypts nt hashes from sam\domains\account\users using bootkey + rid
- decrypts lsa secrets from security\policy\secrets using lsa key + sha256 derivation
- parses lsa_secret structures (version, encKeyID, algorithm, flags, encryptedData)
- performs aes-256/aes-128 decryption with zero-iv block-by-block processing
- extracts dpapi machine/user keys, service passwords, machine credentials
- displays usernames, rids, nt hashes, dpapi keys, service credentials in impacket format

## technical structure

- `main.go` - orchestration and entry point
- `windows.go` - kernel32 api calls (createfilew, readfile, etc)
- `ntfs.go` - boot sector parsing, mft record reading, data run extraction
- `registry.go` - hive structures, nk/vk record parsing, key traversal
- `crypto.go` - bootkey/lsa key extraction, impacket-compatible decryption (sha256Key, decryptLSA, decryptAES)
- `sam.go` - sam/system hive parsing and nt hash extraction
- `lsa.go` - security hive parsing, lsa secret decryption, dpapi key extraction, service credential parsing

## lsa secret decryption

implements impacket's exact lsa secret decryption methodology:

- **lsa key extraction**: uses `decryptLSA()` with boot key + sha256 key derivation (1000 iterations)
- **secret parsing**: parses `LSA_SECRET` structures (version, encKeyID, algorithm, flags, encryptedData)
- **key derivation**: `sha256(lsaKey + salt)` where salt = first 32 bytes of encryptedData
- **aes decryption**: supports aes-256/aes-128 with zero-iv block-by-block processing (impacket behavior)
- **blob parsing**: extracts secrets from `LSA_SECRET_BLOB` structures (length + 12 unknown bytes + secret)
- **secret types**: dpapi_system (machine/user keys), service passwords (utf-16le), machine credentials

output format matches impacket secretsdump.py:
```
dpapi_machinekey: 2ed096bdbb5e8999a2186ec53f03720f07bd7a61
dpapi_userkey: 2be7b390232d4af9b7f98636a371c9f4b951f338
service password: postgres
```

## requirements

- windows os
- administrator privileges
- go 1.16+
- github.com/carved4/go-wincall for winapi interaction
