package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
)

func extractBootKey(hive *RegistryHive) []byte {
	keyNames := []string{"JD", "Skew1", "GBG", "Data"}

	var classNames []byte

	for _, keyName := range keyNames {
		key, err := hive.FindKey("ControlSet001\\Control\\Lsa\\" + keyName)
		if err != nil {
			return nil
		}

		if key.ClassName == "" {
			return nil
		}

		classHexStr := ""
		classBytes := hexStringToBytes(key.ClassName)

		for i := 0; i < len(classBytes); i += 2 {
			if i < len(classBytes) {
				classHexStr += string(classBytes[i])
			}
		}

		actualBytes := hexStringToBytes(classHexStr)
		classNames = append(classNames, actualBytes...)
	}

	if len(classNames) != 16 {
		return nil
	}

	scramble := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

	bootKey := make([]byte, 16)
	for i := 0; i < 16; i++ {
		bootKey[i] = classNames[scramble[i]]
	}

	return bootKey
}

func decryptLSA(value []byte, bootKey []byte, vistaStyle bool) []byte {
	if vistaStyle {

		if len(value) < 28 {
			return nil
		}

		encryptedData := value[28:]

		if len(encryptedData) < 32 {
			return nil
		}

		salt := encryptedData[:32]

		tmpKey := sha256Key(bootKey, salt)

		cipherText := encryptedData[32:]

		plainText := decryptAES(tmpKey, make([]byte, 16), cipherText) // zero IV

		if plainText == nil {
			return nil
		}

		if len(plainText) < 16 {
			return nil
		}

		length := binary.LittleEndian.Uint32(plainText[0:4])

		if len(plainText) < 16+int(length) {
			return nil
		}

		secret := plainText[16 : 16+length]

		if len(secret) < 84 {
			return nil
		}

		lsaKey := secret[52:84]

		return lsaKey
	} else {
		return nil
	}
}

func sha256Key(key []byte, value []byte) []byte {
	h := sha256.New()
	h.Write(key)
	for i := 0; i < 1000; i++ {
		h.Write(value)
	}
	return h.Sum(nil)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func decryptLSAKeyData(encryptedLSAKey []byte, bootKey []byte) []byte {
	return decryptLSA(encryptedLSAKey, bootKey, true)
}

func decryptAES(key, iv, data []byte) []byte {
	var plainText []byte

	zeroIV := make([]byte, 16)
	isZeroIV := true
	for i := 0; i < len(iv) && i < 16; i++ {
		if iv[i] != 0 {
			isZeroIV = false
			break
		}
	}

	if isZeroIV {
		for index := 0; index < len(data); index += 16 {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil
			}

			mode := cipher.NewCBCDecrypter(block, zeroIV)

			cipherBuffer := data[index : index+16]
			if len(cipherBuffer) < 16 {
				padded := make([]byte, 16)
				copy(padded, cipherBuffer)
				cipherBuffer = padded
			}

			decrypted := make([]byte, 16)
			mode.CryptBlocks(decrypted, cipherBuffer)
			plainText = append(plainText, decrypted...)
		}
	} else {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil
		}

		if len(data)%aes.BlockSize != 0 {
			return nil
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		plainText = make([]byte, len(data))
		mode.CryptBlocks(plainText, data)
	}

	return plainText
}

func deriveSHA256Key(key []byte, salt []byte) []byte {
	h := sha256.New()
	h.Write(key)
	for i := 0; i < 1000; i++ {
		h.Write(salt)
	}
	return h.Sum(nil)
}

func decryptSingleDES(key, data []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	decrypted := make([]byte, len(data))
	block.Decrypt(decrypted, data)

	return decrypted
}

func ridToDESKey(rid uint32, index int) []byte {
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	var s []byte
	if index == 1 {
		s = []byte{ridBytes[0], ridBytes[1], ridBytes[2], ridBytes[3], ridBytes[0], ridBytes[1], ridBytes[2]}
	} else {
		s = []byte{ridBytes[3], ridBytes[0], ridBytes[1], ridBytes[2], ridBytes[3], ridBytes[0], ridBytes[1]}
	}

	key := make([]byte, 8)
	key[0] = s[0] >> 1
	key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2)
	key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3)
	key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4)
	key[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5)
	key[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6)
	key[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7)
	key[7] = s[6] & 0x7F

	for i := 0; i < 8; i++ {
		key[i] = (key[i] << 1)
	}

	return key
}

func decryptHashWithBootKey(encryptedHash []byte, bootKey []byte, rid uint32) []byte {
	if len(encryptedHash) < 16 {
		return nil
	}

	if len(encryptedHash) >= 24 {
		if encryptedHash[0] == 0x02 && encryptedHash[1] == 0x00 {
			return decryptHashAES(encryptedHash, bootKey, rid)
		}
	}

	return decryptHashRC4(encryptedHash, bootKey, rid)
}

func decryptHashAES(data []byte, bootKey []byte, rid uint32) []byte {
	if len(data) < 24 {
		return nil
	}

	if len(data) < 32 {
		return make([]byte, 16)
	}

	salt := data[8:24]
	encData := data[24:]

	if len(encData) < 16 {
		return make([]byte, 16)
	}

	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	h := sha256.New()
	h.Write(bootKey)
	h.Write(ridBytes)
	h.Write(salt)
	aesKey := h.Sum(nil)[:16]

	iv := salt[:16]

	decrypted := decryptAES(aesKey, iv, encData[:16])
	if decrypted == nil {
		return nil
	}

	return decrypted
}

func decryptHashRC4(encryptedHash []byte, bootKey []byte, rid uint32) []byte {
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	h := md5.New()
	h.Write(bootKey)
	h.Write(ridBytes)
	rc4Key := h.Sum(nil)

	cipher, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil
	}

	decrypted := make([]byte, len(encryptedHash))
	cipher.XORKeyStream(decrypted, encryptedHash)

	return decrypted
}
