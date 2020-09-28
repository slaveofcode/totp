package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"
)

// base10 with n position base10^n
var hotpDigitsPower = [...]int{
	1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
}

func hmacSHA(crypto func() hash.Hash, msg, secret []byte) []byte {
	mac := hmac.New(crypto, secret)
	mac.Write(msg)
	return mac.Sum(nil)
}

func generateTOTP(secret []byte, hexTime string, digits int, crypto func() hash.Hash) string {
	// First 8 bytes are for the movingFactor
	// Compliant with base RFC 4226 (HOTP)
	for x := len(hexTime); x < 16; x++ {
		hexTime = "0" + hexTime
	}

	msgbytes, _ := hex.DecodeString(hexTime)
	hashBytes := hmacSHA(crypto, msgbytes, secret)

	// get the last byte and do bitwise and with 4 bits
	offset := hashBytes[len(hashBytes)-1] & 0xf

	firstPart := int32(hashBytes[offset] & 0x7f)
	secondPart := int32(hashBytes[offset+1] & 0xff)
	thirdPart := int32(hashBytes[offset+2] & 0xff)
	fourthPart := int32(hashBytes[offset+3] & 0xff)

	binary := firstPart<<24 |
		secondPart<<16 |
		thirdPart<<8 |
		fourthPart

	otp := int(binary) % hotpDigitsPower[digits]
	result := strconv.Itoa(otp)
	for x := len(result); x < digits; x++ {
		result = "0" + result
	}

	return result
}

func printTable() {
	// // Seed for HMAC-SHA1 - 20 bytes
	seed, _ := hex.DecodeString("3132333435363738393031323334353637383930")
	// Seed for HMAC-SHA256 - 32 bytes
	seed32, _ := hex.DecodeString("3132333435363738393031323334353637383930" +
		"313233343536373839303132")
	// Seed for HMAC-SHA512 - 64 bytes
	seed64, _ := hex.DecodeString("3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"31323334")
	timeTests := []int64{
		58,
		59,
		60,
		61,
		89,
		90,
		1111111109,
		1111111111,
		1234567890,
		2000000000,
		20000000000,
	}

	fmt.Println(
		"+ -------------------+---------------------------------+" + "------------------+---------+----------+")
	fmt.Println(
		"|       Time(sec)    |         Time (UTC format)       " + "| Value of T(Hex)  |   TOTP  |   Mode   |")
	fmt.Println(
		"+--------------------+---------------------------------+" + "------------------+---------+----------+")

	var T0 int64 = 0
	var X int64 = 30
	digit := 8
	for _, timeParam := range timeTests {
		T := (timeParam - T0) / X
		timeHex := strings.ToUpper(fmt.Sprintf("%x", T))

		for x := len(timeHex); x < 16; x++ {
			timeHex = "0" + timeHex
		}

		timeParamDisplay := strconv.Itoa(int(timeParam))
		for x := len(timeParamDisplay); x < 16; x++ {
			timeParamDisplay = timeParamDisplay + " "
		}

		res := generateTOTP(seed, timeHex, digit, sha1.New)
		fmt.Print("|  ", timeParamDisplay, "  |  ", time.Unix(timeParam, 0).UTC(), "  | ", timeHex, " |")
		fmt.Println(res, "| SHA1     |")

		res2 := generateTOTP(seed32, timeHex, digit, sha256.New)
		fmt.Print("|  ", timeParamDisplay, "  |  ", time.Unix(timeParam, 0).UTC(), "  | ", timeHex, " |")
		fmt.Println(res2, "| SHA256   |")

		res3 := generateTOTP(seed64, timeHex, digit, sha512.New)
		fmt.Print("|  ", timeParamDisplay, "  |  ", time.Unix(timeParam, 0).UTC(), "  | ", timeHex, " |")
		fmt.Println(res3, "| SHA512   |")

		fmt.Println("+ -------------------+---------------------------------+" + "------------------+---------+----------+")
	}
}

func showKey(base32Secret string, digit int, interval int64) {
	T0 := int64(0)
	byteSecret, _ := base32.StdEncoding.DecodeString(strings.ToUpper(base32Secret))

	for {
		currUnixTime := time.Now().Unix()
		T := (currUnixTime - T0) / interval
		timeHex := strings.ToUpper(fmt.Sprintf("%x", T))

		// left padding
		for x := len(timeHex); x < 16; x++ {
			timeHex = "0" + timeHex
		}

		fmt.Println("Current Key:", generateTOTP(byteSecret, timeHex, digit, sha1.New))
		time.Sleep(time.Second * 2)
	}
}

func main() {
	// showKey("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", 6, 30)
	printTable()
}
