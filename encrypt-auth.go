package main

import ("os"
//	"bytes"
	"encoding/hex"
	"fmt"
	"crypto/sha256"
	"crypto/rand"
	"crypto/aes"
	"strings"
	"math"
	"strconv"
	"io/ioutil"
)

func hmacKey(key []byte, message []byte) []byte{
	var i int
	tag := make([]byte, 32)
	keyArg := make([]byte, 100000)

	//fix first case
	if(len(key) > len(message)){
		fmt.Println("\nKey is longer")
		//keyNew := make([]byte, 32) 
		keyNew := sha256.Sum256(key)
		fmt.Printf("\nModified HMAC key is: %x ",keyNew)
		for i = 0; i < len(keyNew); i++{
			keyArg[i] = keyNew[i]
		} 
		tag = hmac(keyArg[0:len(keyNew)], message)

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
		tag = hmac(keyNew, message)
	}

	return tag
	
 
}


func hmac(hmacKey []byte, message []byte) []byte{

	var i int
	finalTag := make([]byte, 32)
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

	for i = 0; i < len(finalMessSha); i++{
		finalTag[i] = finalMessSha[i]
	}
        return finalTag
	
	

}

func decryptCipher(message []byte, keyD []byte, keyM []byte){

	fmt.Println("\n Length of message",len(message))
	var i int
	initVector := message[0:16]
	realMessage := message[16:len(message)]
	
	fmt.Println("\n")
	fmt.Println(len(initVector))
	fmt.Println(len(realMessage))
	decryptedMess := make([]byte, len(realMessage))

	rounds := len(realMessage)/16
	currCipherBlock := make([]byte, 16)
	prevCipherBlock := make([]byte, 16)
	currResultBlock := make([]byte, 16)
	xorBlock := make([]byte, 16)
	index := len(realMessage)

	cipherDecrypt, err := aes.NewCipher(keyD)
        if err != nil{
                panic (err)
        }

	for rounds > 0{
		currCipherBlock = realMessage[index-16:index]
		if rounds == 1{
			prevCipherBlock = initVector
		}else{
			prevCipherBlock = realMessage[index-32:index-16]
		}

		fmt.Println("\n Current Cipher Block is: %x", currCipherBlock)
		fmt.Println("\n Previous Cipher Block is: %x", prevCipherBlock)
		cipherDecrypt.Decrypt(currResultBlock, currCipherBlock)
		for i = 0; i < len(currResultBlock); i++{
			xorBlock[i] = currResultBlock[i] ^ prevCipherBlock[i]
		}
		j := 0
		for i = index-16; i < index; i++{
			decryptedMess[i] = xorBlock[j]
			j++
		}
		index -= 16
		rounds -=1
	}	

	fmt.Printf("Complete Decrypted Message is: %x", decryptedMess)
	padCheck := true
	lastByte := int(decryptedMess[len(decryptedMess)-1])
	for i = len(decryptedMess)-1; i >= len(decryptedMess)-lastByte; i--{
		if int(decryptedMess[i]) != lastByte{
			fmt.Println("\n INVALID PADDING")
			padCheck = false
			break
		}
	}
	decryptedMessNoPad := make([]byte, len(decryptedMess)-lastByte)
	if padCheck == true{
		decryptedMessNoPad = decryptedMess[0: len(decryptedMess)-lastByte]
	}

	fmt.Printf("\nMessage without Pad is: %x\n", decryptedMessNoPad)
	
	//Stripping HMAC Tag

	stripTag := make([]byte, 32)

}


func main(){
	
	var i int
	plainBuf := make([]byte, 100000)
	mainKey := os.Args[1]
	macKey := make([]byte, 16)
        copy(macKey[:],mainKey[16:32])
	encKey := make([]byte, 16)
	copy(encKey[:],mainKey[0:16])
	macKeyHex := make([]byte, 32)
	hex.Encode(macKeyHex, macKey)
	encKeyHex := make([]byte, 32)
	hex.Encode(encKeyHex, encKey)
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

	// Begin calculating Hash

	hmacTag := hmacKey(macKeyHex, plainBufNewHex)
	fmt.Println("\nHMAC Tag is:", hmacTag)
	 
	// Begin Encryption here

	hashedMessLen := len(hmacTag) + len(plainBufNewHex)
	hashedMess := make([]byte, hashedMessLen)
	for i = 0; i < len(plainBufNewHex); i++{
		hashedMess[i] = plainBufNewHex[i]
	}  		 

	for i = 0 ; i < len(hmacTag); i++{
		hashedMess[i+len(plainBufNewHex)] = hmacTag[i]
	}

	extraLen := hashedMessLen % 16
	if extraLen < 0{
		extraLen = extraLen + 16
	}
	extraLenFinal := extraLen
	
	padding := make([]byte, 16-extraLen)
	
	if extraLenFinal != 0{

		padByte := int(math.Pow(float64(16-extraLen), 2))
		fmt.Println("\n")
		fmt.Println("\n PadByte is: ")
		fmt.Println(padByte)
		padByteStr := strconv.Itoa(padByte)
		fmt.Printf("PadByte String is %s: ", padByteStr)
		padByteBuf := strings.Repeat(padByteStr, 16-extraLen)
		padding, err = hex.DecodeString(padByteBuf)
		if err!=nil{
			panic(err)
		}

		fmt.Printf("Padding string is: %x",padding)
	}

	if extraLenFinal == 0{
		padByte := 10
                fmt.Println("\n")
                fmt.Println("\n PadByte is: ")
                fmt.Println(padByte)
                padByteStr := strconv.Itoa(padByte)
                fmt.Printf("PadByte String is %s: ", padByteStr)
                padByteBuf := strings.Repeat(padByteStr, 16)
                padding, err = hex.DecodeString(padByteBuf)
                if err!=nil{
                        panic(err)
                }

                fmt.Printf("Padding string is: %x",padding)

	}

	completeMess := make([]byte, hashedMessLen+len(padding))
	for i = 0; i < hashedMessLen; i++{
		completeMess[i] = hashedMess[i]
	} 
	for i = 0; i < len(padding); i++{
		completeMess[i+ hashedMessLen] = padding[i]
	}

	fmt.Printf("\nComplete Message is: %x", completeMess)
	
	// Generating IV
	
	rawIV := make([]byte, 8)
	IV := make([]byte, hex.EncodedLen(len(rawIV)))
	rand.Read(rawIV)
	hex.Encode(IV, rawIV)
	xorBlock := IV
	finalBlock := make([]byte, 16)
	cipherBlock := make([]byte, 16)

	cipherEncrypt, err := aes.NewCipher(encKeyHex)
	if err != nil{
		panic (err)
	}

	fmt.Println("\nInitialization Vector is:")
	fmt.Println(IV)
	fmt.Printf("\nTotal length is %d", len(completeMess))
	rounds := len(completeMess)/16
	fmt.Printf("\n %d number of rounds", rounds)
	IVwithCipher := make([]byte, len(completeMess)+len(IV))
	for i = 0; i < len(IV);  i++{
		IVwithCipher[i] = IV[i]
	}
	var index int = 0
	for rounds > 0{
		
		messBlock := completeMess[index:index+16]
		for i =0; i < len(messBlock); i++{
			finalBlock[i] = messBlock[i] ^ xorBlock[i] 
		} 
		cipherEncrypt.Encrypt(cipherBlock, finalBlock)
		fmt.Printf("\n Cipherblock: %x", cipherBlock)
	
		for i = 0; i < len(cipherBlock); i++{
			IVwithCipher[16 + index + i] = cipherBlock[i]
		}		
		xorBlock = cipherBlock

		index += 16
		rounds -= 1
	}

	ioutil.WriteFile(os.Args[3], IVwithCipher, 0666)



	///////////////////////////////////////////////////////////

	// Prepare for Decrypt function
	rawCiphertext := make([]byte, 100000)
	fi, err = os.Open("ciphertext.txt")
	if err != nil{
		panic(err)
	}

	fi.Read(rawCiphertext)
	for i = 0; i < len(rawCiphertext); i++{
		if rawCiphertext[i] == 0{
			break;
		}
	}
	rawCiphertextLen := i
	rawCiphertextNew := make([]byte,rawCiphertextLen)
	rawCiphertextNew = rawCiphertext[0:rawCiphertextLen]

	decryptCipher(rawCiphertextNew, encKeyHex, macKeyHex)

}
