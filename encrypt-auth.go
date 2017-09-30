package main

import ("os"
//	"bytes"
	"encoding/hex"
	"fmt"
	"crypto/sha256"
)

func hmac(key []byte, message []byte) []byte{
	var i int
	//fix first case
	if(len(key) > len(message)){
		keyNew := sha256.Sum256(key)
		fmt.Println(keyNew)

	}

	if(len(key) < len(message)){
		numPad := len(message) - len(key)
		padBuf := make([]byte, numPad)
		for i = 0; i < numPad; i++{
			padBuf[i] = 0
		} 
		keyNewBig := make([]byte, numPad+len(key))
		keyNewBig = append(key)
		keyNewBig = append(padBuf)
		fmt.Println(keyNewBig)
	}

	return []byte("hello")
}

func main(){
	
	var i int
	plainBuf := make([]byte, 100000)
	mainKey := os.Args[1]
	macKey := make([]byte, 16)
        copy(macKey[:],mainKey[16:32])
	macKeyHex := make([]byte, 32)
	hex.Encode(macKeyHex, macKey)
        fmt.Println(macKey)
	fmt.Printf("%s\n",macKeyHex) 

	fi, err := os.Open(os.Args[2])
	if err != nil{
		panic(err)
	}
	fi.Read(plainBuf)
	//fmt.Println(len(plainBufNew))
	for i = 0; i < len(plainBuf); i++{
		if plainBuf[i] == 0{
			break
		}
	}
	plainBufLen := i
	plainBufNew := make([]byte, plainBufLen)
	plainBufNew = plainBuf[0:plainBufLen]
	fmt.Println(plainBufNew)

	//Begin calculating Hash

	
	hmac(macKeyHex, plainBufNew)
	 
	 














}
