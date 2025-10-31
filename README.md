# ntfsparse

a windows credential extractor that directly reads the sam and system registry hives from the ntfs filesystem at the raw disk level. bypasses file locks by opening the volume handle directly and parsing the master file table (mft) to locate and extract registry hive files. implements full registry hive parsing including nk (key node) and vk (value key) structures, extracts the bootkey from system hive class names using the lsa key scrambling algorithm, and decrypts nt password hashes using aes-128-cbc (windows 10+) or rc4-md5 (legacy) with rid-based key derivation. supports both modern and legacy windows encryption schemes.

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
- extracts `C:\Windows\System32\config\SAM` and `SYSTEM` hives via mft parsing
- derives bootkey from system\controlset001\control\lsa key class names
- decrypts nt hashes from sam\domains\account\users using bootkey + rid
- displays usernames, rids, account status, and nt hashes

## technical structure

- `main.go` - orchestration and entry point
- `windows.go` - kernel32 api calls (createfilew, readfile, etc)
- `ntfs.go` - boot sector parsing, mft record reading, data run extraction
- `registry.go` - hive structures, nk/vk record parsing, key traversal
- `crypto.go` - bootkey extraction, aes/des/rc4 decryption algorithms
- `sam.go` - sam/system hive parsing and credential extraction

## requirements

- windows os
- administrator privileges
- go 1.16+
- github.com/carved4/go-wincall for syscall wrappers

