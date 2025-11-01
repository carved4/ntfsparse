package main

import (
	"fmt"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

func logonUserNonDomainJoined(user string, pass string) uintptr {
	a32Base := wc.LoadLibraryLdr("advapi32.dll")
	logonUserW := wc.GetFunctionAddress(a32Base, wc.GetHash("LogonUserW"))
	getLastError := wc.GetFunctionAddress(wc.GetModuleBase(wc.GetHash("kernel32.dll")), wc.GetHash("GetLastError"))
	username := user
	domain := "."
	logonType := uintptr(3)
	provider := uintptr(0)

	userPtr16, _ := wc.UTF16ptr(username)
	userPtr := uintptr(unsafe.Pointer(userPtr16))
	domainPtr16, _ := wc.UTF16ptr(domain)
	domainPtr := uintptr(unsafe.Pointer(domainPtr16))
	passPtr16, _ := wc.UTF16ptr(pass)
	passPtr := uintptr(unsafe.Pointer(passPtr16))
	var hToken uintptr

	ret, _, _ := wc.CallG0(logonUserW, userPtr, domainPtr, passPtr, logonType, provider, uintptr(unsafe.Pointer(&hToken)))
	if ret != 0 {
		fmt.Printf("[+] logged on as user: %s successfully! token: %x\n", user, hToken)
		return hToken
	}

	errCode, _, _ := wc.CallG0(getLastError)
	fmt.Printf("[-] failed with error code: %d\n", errCode)
	return 0
}

// untested
func logonUserDomainJoined(user string, pass string, domain string) uintptr {
	a32Base := wc.LoadLibraryLdr("advapi32.dll")
	logonUserW := wc.GetFunctionAddress(a32Base, wc.GetHash("LogonUserW"))
	getLastError := wc.GetFunctionAddress(wc.GetModuleBase(wc.GetHash("kernel32.dll")), wc.GetHash("GetLastError"))
	username := user
	logonType := uintptr(3)
	provider := uintptr(0)

	userPtr16, _ := wc.UTF16ptr(username)
	userPtr := uintptr(unsafe.Pointer(userPtr16))
	domainPtr16, _ := wc.UTF16ptr(domain)
	domainPtr := uintptr(unsafe.Pointer(domainPtr16))
	passPtr16, _ := wc.UTF16ptr(pass)
	passPtr := uintptr(unsafe.Pointer(passPtr16))
	var hToken uintptr

	ret, _, _ := wc.CallG0(logonUserW, userPtr, domainPtr, passPtr, logonType, provider, uintptr(unsafe.Pointer(&hToken)))
	if ret != 0 {
		fmt.Printf("[+] success! token: %x\n", hToken)
		return hToken
	}

	errCode, _, _ := wc.CallG0(getLastError)
	fmt.Printf("[-] failed with error code: %d\n", errCode)
	return 0
}

func impersonateToken(hToken uintptr) {
	a32Base := wc.LoadLibraryLdr("advapi32.dll")
	impersonateLoggedOnUser := wc.GetFunctionAddress(a32Base, wc.GetHash("ImpersonateLoggedOnUser"))
	ret, _, _ := wc.CallG0(impersonateLoggedOnUser, hToken)
	if ret != 0 {
		fmt.Printf("[+] impersonation successful\n")
	} else {
		fmt.Printf("[-] impersonation failed\n")
	}
}

func setThreadToken(hToken uintptr) bool {
	a32Base := wc.LoadLibraryLdr("advapi32.dll")
	setThreadToken := wc.GetFunctionAddress(a32Base, wc.GetHash("SetThreadToken"))

	var hNewToken uintptr
	dupTokenEx := wc.GetFunctionAddress(a32Base, wc.GetHash("DuplicateTokenEx"))

	ret, _, _ := wc.CallG0(
		dupTokenEx,
		hToken,
		0x02000000,
		0,
		2,
		2,
		uintptr(unsafe.Pointer(&hNewToken)),
	)

	if ret == 0 {
		return false
	}

	ret, _, err := wc.CallG0(
		setThreadToken,
		0,
		hNewToken,
	)

	if ret == 0 {
		fmt.Printf("[-] SetThreadToken failed: %v\n", err)
		return false
	}

	fmt.Println("[+] thread token set!")
	return true
}

func enablePrivilege(hToken uintptr, privilegeName string) bool {
	a32Base := wc.LoadLibraryLdr("advapi32.dll")
	lookupPriv := wc.GetFunctionAddress(a32Base, wc.GetHash("LookupPrivilegeValueW"))
	adjustPriv := wc.GetFunctionAddress(a32Base, wc.GetHash("AdjustTokenPrivileges"))
	getLastError := wc.GetFunctionAddress(wc.GetModuleBase(wc.GetHash("kernel32.dll")), wc.GetHash("GetLastError"))

	privNamePtr, _ := wc.UTF16ptr(privilegeName)

	var luid int64
	ret, _, _ := wc.CallG0(
		lookupPriv,
		0,
		uintptr(unsafe.Pointer(privNamePtr)),
		uintptr(unsafe.Pointer(&luid)),
	)

	if ret == 0 {
		fmt.Printf("[-] failed to lookup privilege: %s\n", privilegeName)
		return false
	}

	type TokenPrivileges struct {
		PrivilegeCount uint32
		Luid           int64
		Attributes     uint32
	}

	tp := TokenPrivileges{
		PrivilegeCount: 1,
		Luid:           luid,
		Attributes:     2,
	}

	ret, _, _ = wc.CallG0(
		adjustPriv,
		hToken,
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	errCode, _, _ := wc.CallG0(getLastError)

	if ret != 0 && errCode == 0 {
		fmt.Printf("[+] enabled privilege: %s\n", privilegeName)
		return true
	} else if errCode == 1300 {
		fmt.Printf("[-] privilege %s not held by token (can't enable)\n", privilegeName)
		return false
	}

	fmt.Printf("[-] failed to enable privilege: %s (error: %d)\n", privilegeName, errCode)
	return false
}

func listTokenPrivileges(hToken uintptr) {
	a32Base := wc.LoadLibraryLdr("advapi32.dll")
	getTokenInfo := wc.GetFunctionAddress(a32Base, wc.GetHash("GetTokenInformation"))
	lookupPrivName := wc.GetFunctionAddress(a32Base, wc.GetHash("LookupPrivilegeNameW"))
	var returnLength uint32
	wc.CallG0(
		getTokenInfo,
		hToken,
		3,
		0,
		0,
		uintptr(unsafe.Pointer(&returnLength)),
	)

	buffer := make([]byte, returnLength)
	ret, _, _ := wc.CallG0(
		getTokenInfo,
		hToken,
		3,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(returnLength),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret == 0 {
		fmt.Println("[-] failed to get token privileges")
		return
	}

	privilegeCount := *(*uint32)(unsafe.Pointer(&buffer[0]))

	fmt.Printf("[+] token has %d privileges:\n", privilegeCount)
	offset := 4

	for i := uint32(0); i < privilegeCount; i++ {
		luid := *(*int64)(unsafe.Pointer(&buffer[offset]))
		attributes := *(*uint32)(unsafe.Pointer(&buffer[offset+8]))
		nameBuffer := make([]uint16, 256)
		nameSize := uint32(256)
		ret, _, _ := wc.CallG0(
			lookupPrivName,
			0,
			uintptr(unsafe.Pointer(&luid)),
			uintptr(unsafe.Pointer(&nameBuffer[0])),
			uintptr(unsafe.Pointer(&nameSize)),
		)
		if ret != 0 {
			name := ""
			for j := uint32(0); j < nameSize && nameBuffer[j] != 0; j++ {
				name += string(rune(nameBuffer[j]))
			}
			enabled := ""
			if attributes&0x00000002 != 0 {
				enabled = " [ENABLED]"
			}
			if attributes&0x00000001 != 0 {
				enabled += " [DEFAULT]"
			}
			fmt.Printf("    %s%s\n", name, enabled)
		}
		offset += 12
	}
}

func getCurrentProcessToken() uintptr {
	k32Base := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	a32Base := wc.LoadLibraryLdr("advapi32.dll")

	getCurrentProcess := wc.GetFunctionAddress(k32Base, wc.GetHash("GetCurrentProcess"))
	openProcessToken := wc.GetFunctionAddress(a32Base, wc.GetHash("OpenProcessToken"))

	hProcess, _, _ := wc.CallG0(getCurrentProcess)

	var hToken uintptr
	wc.CallG0(
		openProcessToken,
		hProcess,
		0x0028,
		uintptr(unsafe.Pointer(&hToken)),
	)

	return hToken
}
