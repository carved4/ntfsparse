# ntfsparse

# demo
<img width="1008" height="727" alt="livedc" src="https://github.com/user-attachments/assets/8edb08ae-f3b5-49c8-999a-19c2fa5be0ae" />

a windows credential extractor that directly reads sam, system, security registry hives, and ntds.dit from the ntfs filesystem at the raw disk level. bypasses file locks by opening the volume handle directly and parsing the master file table (mft) to locate and extract registry hive files. implements full registry hive parsing including nk (key node) and vk (value key) structures, extracts the bootkey from system hive class names using the lsa key scrambling algorithm, derives the lsa encryption key from the bootkey using impacket-compatible methods, and decrypts both nt password hashes (using aes-128-cbc for windows 10+ or rc4-md5 for legacy) and lsa secrets (dpapi system keys, service account passwords, machine account credentials, cached domain credentials). on domain controllers, automatically creates volume shadow copy snapshots via vssadmin to extract locked ntds.dit files, parses ese database structures using go-ese library, extracts and decrypts the password encryption key (pek) from datatable, and decrypts all domain user nt password hashes using md5/rc4 cryptography. features implementation of impacket's lsa secret decryption including lsa_secret/lsa_secret_blob structure parsing, sha256 key derivation with 1000 iterations, and aes-256/aes-128 decryption with zero-iv handling. supports both modern and legacy windows encryption schemes with raw disk parsing requiring no windows registry apis.

## build

```bash
go get www.velocidex.com/golang/go-ese@v0.2.0
go get github.com/Velocidex/ordereddict
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
- extracts `sam`, `system`, and `security` hives via mft parsing
- derives bootkey from system\controlset001\control\lsa key class names
- derives lsa key from bootkey using polsecretencryptionkey (impacket-compatible)
- decrypts nt hashes from sam\domains\account\users using bootkey + rid
- decrypts lsa secrets from security\policy\secrets using lsa key + sha256 derivation
- parses lsa_secret structures (version, encKeyID, algorithm, flags, encryptedData)
- performs aes-256/aes-128 decryption with zero-iv block-by-block processing
- extracts dpapi machine/user keys, service passwords, machine credentials
- displays usernames, rids, nt hashes, dpapi keys, service credentials in impacket format
- detects domain controllers and creates vss shadow copy to extract ntds.dit
- parses ese database catalog and datatable structures
- extracts pek (password encryption key) from attk590689 attribute
- decrypts pek using bootkey with sha256 key derivation (modern) or md5/rc4 (legacy)
- extracts all user objects by scanning for attm590045 (samaccountname)
- decrypts user password hashes (attk589914 unicodepwd) using pek + md5/rc4
- saves all domain credentials to ntds_hashes.txt in username:nthash format
- automatically cleans up vss shadow copies after extraction

## technical structure

- `main.go` - orchestration and entry point
- `windows.go` - kernel32 api calls (createfilew, readfile, etc)
- `ntfs.go` - boot sector parsing, mft record reading, data run extraction
- `registry.go` - hive structures, nk/vk record parsing, key traversal
- `crypto.go` - bootkey/lsa key extraction, pek decryption, hash decryption (sha256, aes, md5, rc4)
- `sam.go` - sam/system hive parsing and nt hash extraction
- `lsa.go` - security hive parsing, lsa secret decryption, dpapi key extraction, service credential parsing, machine account password extraction
- `ntds.go` - vss shadow copy creation, ese database parsing, pek extraction, domain user hash decryption

## ntds.dit extraction and parsing

implements active directory credential extraction from domain controllers:

- vss shadow copy creation: executes `vssadmin create shadow /for=c:` via createprocessw
- ntds.dit extraction: copies locked database from shadow copy snapshot
- ese database parsing: uses velocidex go-ese library to read catalog and datatable
- pek extraction: scans datatable for attk590689 (pekList) attribute
- pek decryption: modern windows (2016+) uses sha256 key derivation with configurable rounds + aes-256-cbc, legacy uses md5 + rc4
- user enumeration: iterates datatable for attm590045 (samaccountname) to identify user objects
- hash decryption: extracts attk589914 (unicodepwd), derives key via md5(pek + salt), decrypts with rc4
- output: saves all credentials to ntds_hashes.txt for offline cracking with hashcat/john

pek structure (modern):
```
[version 4][flags 4][salt 16][rounds 4][encrypted pek list...]
key = sha256(bootkey + salt) iterated rounds times
decrypt with aes-256-cbc zero-iv
```

hash structure:
```
[header 8][salt 16][encrypted nt hash 16]
key = md5(pek + salt)
decrypt with rc4
```

output format:
```
Administrator:192f54a9b9b0381df8e21c42ed06ed59
dc:7527d4e483db3c26c21f0f43826ec5d7
SSSSS$:9d077687909b1728ee5c34b57f70e792
krbtgt:1d78c169a5edaafa3110c3e50a4d600d
JANNIE_BLEVINS:45033663f64fd9b479db82422bcb0da7
TAMERA_HARDIN:9927eb7e455cf0447ba7510a36232f0b
STACEY_ROBERTSON:a0a530bafdf007f388a111ab0aece74e
KIRK_WALSH:739dfcd60002c98e23458a6d5e070df9
LESA_SWEET:c4167630073c86bda914da95b9ace11a
EVANGELINA_COMBS:7fe0e096b1f9aed1f7fa62fa6c00210e
... and 2581 more
```

## requirements

- windows os
- administrator privileges
- go 1.16+
- github.com/carved4/go-wincall for winapi interaction
- www.velocidex.com/golang/go-ese for ese database parsing
- github.com/velocidex/ordereddict for ese table enumeration
