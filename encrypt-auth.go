package main

import ("os"
//	"bytes"
	"encoding/hex"
	"fmt"
	"crypto/sha256"
)

func hmac(key []byte, message []byte) []byte{

	//fix first case
	if(len(key) > len(message)){
		keyNew := sha256.Sum256(key)
		return keyNew
	}

	if(len(key) < len(message)){
		numPad := len(message) - len(key)
		padBuf := make([]byte, numPad)
		keyNewBig := make([]byte, numPad+len(key))
		keyNewBig = append(key[:], padBuf[:])
		return keyNewBig
	}

	
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

	

	 
	 














}
