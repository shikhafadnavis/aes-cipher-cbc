package main

import ("os"
//	"bytes"
	"encoding/hex"
	"fmt"
	"crypto/sha256"
	"strings"
)

func modifiedKey(key []byte, message []byte){
	var i int

	//fix first case
	if(len(key) > len(message)){
		fmt.Println("\nKey is longer")
		//keyNew := make([]byte, 32) 
		keyNew := sha256.Sum256(key)
		fmt.Printf("\nModified HMAC key is: %x ",keyNew)
		hmac1(keyNew, message)

	}

	if(len(key) < len(message)){
		fmt.Println("\nMessage is longer")
		numPad := len(message) - len(key)
		padBuf := make([]byte, numPad)
		for i = 0; i < numPad; i++{
			padBuf[i] = 0
		} 
		keyNew := make([]byte, numPad+len(key))
		for i = 0; i < len(key); i++{
			keyNew[i] = key[i]
		}
		for i = 0; i < numPad; i++{
			keyNew[i+len(key)] = padBuf[i]
		} 
		fmt.Println("\nModified HMAC Key is: ")
		fmt.Printf("%s",keyNew)
		hmac2(keyNew, message)
	}


}


func hmac1(hmacKey [32]byte, message []byte) []byte{

	var i int
	keyLen := len(hmacKey)
	ipad := strings.Repeat("36", keyLen)
	opad := strings.Repeat("5c", keyLen)
        ipadHex, err := hex.DecodeString(ipad)
        if err != nil{
                panic(err)
        }
	opadHex, err := hex.DecodeString(opad)
	if err != nil{
                panic(err)
        }

        fmt.Println("\nValue of ipad is: ")
        fmt.Printf("%x",ipadHex)
	fmt.Println("\nValue of opad is: ")
        fmt.Printf("%x",opadHex)

        ipadKey := make([]byte, keyLen)
        for i = 0; i < keyLen; i++{
                ipadKey[i] = ipadHex[i] ^ hmacKey[i]
        }
        fmt.Printf("ipadkey is: %x", ipadKey)

	opadKey := make([]byte, keyLen)
        for i = 0; i < keyLen; i++{
                opadKey[i] = opadHex[i] ^ hmacKey[i]
        }
        fmt.Printf("opadkey is: %x", opadKey)

	//Concatenating message to ipad
	totalLen := keyLen + len(message)
	concatMess := make([]byte, totalLen)
	for i = 0; i < keyLen; i++{
		concatMess[i] = ipadKey[i] 
	}
	for i = 0; i < len(message); i++{
                concatMess[i+keyLen] = message[i] 
        }

	//Concatenating opad with previous result
	concatMessSha := sha256.Sum256(concatMess)
	fmt.Printf("\nConcatMessSha is: %x", concatMessSha)
	finalLen := len(opadKey) + len(concatMessSha)
	finalMess := make([]byte, finalLen)
	for i = 0; i < len(opadKey); i++{
		finalMess[i] = opadKey[i]
	}
	for i = 0; i < len(concatMessSha); i++{
		finalMess[i+len(opadKey)] = concatMessSha[i]
	}

	finalMessSha := sha256.Sum256(finalMess)
	fmt.Printf("The HMAC tag is: %x", finalMessSha)

	
        return []byte("Hello")
	
	

}

func hmac2(hmacKey []byte, message []byte) []byte{

        var i int
        keyLen := len(hmacKey)
        ipad := strings.Repeat("36", keyLen)
        ipadHex, err := hex.DecodeString(ipad)
        if err != nil{
                panic(err)
        }
        fmt.Println("\nValue of ipad is: ")
        fmt.Printf("%x",ipadHex)

        ipadKey := make([]byte, keyLen)
        for i = 0; i < keyLen; i++{
                ipadKey[i] = ipadHex[i] ^ hmacKey[i]
        }
        fmt.Printf("ipadkey is: %x", ipadKey)
        return []byte("Hello")


}


func main(){
	
	var i int
	plainBuf := make([]byte, 100000)
	mainKey := os.Args[1]
	macKey := make([]byte, 16)
        copy(macKey[:],mainKey[16:32])
	macKeyHex := make([]byte, 32)
	hex.Encode(macKeyHex, macKey)
        fmt.Println("\nMac key is: ")
	fmt.Println(macKey)
	fmt.Printf("\n Hex Mac Key is: %s",macKeyHex) 

	fi, err := os.Open(os.Args[2])
	if err != nil{
		panic(err)
	}
	fi.Read(plainBuf)
	//fmt.Println(len(plainBufNew))
	for i = 0; i < len(plainBuf); i++{
		if plainBuf[i] == 10{
			break
		}
	}
	plainBufLen := i
	plainBufNew := make([]byte, plainBufLen)
	plainBufNew = plainBuf[0:plainBufLen]
	fmt.Println("\nPlaintext is: ")
	fmt.Println(plainBufNew)
	plainBufNewHex := make([]byte, hex.EncodedLen(len(plainBufNew)))
	hex.Encode(plainBufNewHex, plainBufNew)
	fmt.Printf("\nHex Plaintext is: %s",plainBufNewHex)

	//Begin calculating Hash

	
	modifiedKey(macKeyHex, plainBufNewHex)
	//hmac(hmacKey, plainBufNewHex)
	 
	 














}
