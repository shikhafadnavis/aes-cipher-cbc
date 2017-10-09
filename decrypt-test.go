
package main

import ("os"
//      "bytes"
        "encoding/hex"
        "fmt"
//        "errors"
        "crypto/sha256"
//        "crypto/rand"
        "crypto/aes"
        "strings"
//      "strconv"
        "io/ioutil"
)

func hmacKey(key []byte, message []byte) []byte{
	var i int
	tag := make([]byte, 32)
	keyArg := make([]byte, 100000)

	//fix first case
	if(len(key) > len(message)){
		//fmt.Println("\nKey is longer")
		//keyNew := make([]byte, 32) 
		keyNew := sha256.Sum256(key)
		//fmt.Printf("\nModified HMAC key is: %x ",keyNew)
		for i = 0; i < len(keyNew); i++{
			keyArg[i] = keyNew[i]
		} 
		tag = hmac(keyArg[0:len(keyNew)], message)

	}

	if(len(key) < len(message)){
		//fmt.Println("\nMessage is longer")
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
		//fmt.Println("\nModified HMAC Key is: ")
		//fmt.Printf("%s",keyNew)
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

        //fmt.Println("\nValue of ipad is: ")
        //fmt.Printf("%x",ipadHex)
	//fmt.Println("\nValue of opad is: ")
        //fmt.Printf("%x",opadHex)

        ipadKey := make([]byte, keyLen)
        for i = 0; i < keyLen; i++{
                ipadKey[i] = ipadHex[i] ^ hmacKey[i]
        }
        //fmt.Printf("ipadkey is: %x", ipadKey)

	opadKey := make([]byte, keyLen)
        for i = 0; i < keyLen; i++{
                opadKey[i] = opadHex[i] ^ hmacKey[i]
        }
        //fmt.Printf("opadkey is: %x", opadKey)

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
	//fmt.Printf("\nConcatMessSha is: %x", concatMessSha)
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
	
	//fmt.Println("\n Length of message",len(message))
	var i int
	initVector := message[0:16]
	realMessage := message[16:len(message)]
	
	//fmt.Println("\n")
	//fmt.Println(len(initVector))
	//fmt.Println(len(realMessage))
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
	lastByte := decryptedMess[len(decryptedMess)-1]

	//fmt.Println("\n Last Byte is: ", lastByte)
	for i = len(decryptedMess)-1; i >= len(decryptedMess)-int(lastByte); i--{
		if (decryptedMess[i]) != (lastByte){
			fmt.Println("INVALID PADDING")
			padCheck = false
			break
		}
	}
	decryptedMessNoPad := make([]byte, len(decryptedMess)-int(lastByte))
	if padCheck == true{
		decryptedMessNoPad = decryptedMess[0: len(decryptedMess)-int(lastByte)]
	

		//fmt.Printf("\nMessage without Pad is: %x\n", decryptedMessNoPad)
		decryptedMessNoPadLen := len(decryptedMessNoPad)
		//Stripping HMAC Tag

		stripMess := decryptedMessNoPad[0:decryptedMessNoPadLen-32]
		tag := decryptedMessNoPad[decryptedMessNoPadLen-32:decryptedMessNoPadLen]

		//fmt.Printf("\n Stripped Message: %x", stripMess)
		//fmt.Printf("\n Stripped Tag is %x", tag)

		// Verify Tag
		tagCheck := true
		verifiedTag := hmacKey(keyM, stripMess)
		for i = 0; i < len(verifiedTag); i++{
			if verifiedTag[i] != tag[i]{
				fmt.Println("INVALID MAC")
				tagCheck = false
				break
			}
		}
		
		if tagCheck == true{
			//output to file
			//stripMessDec := make([]byte, hex.DecodedLen(len(stripMess)))
			fmt.Println("SUCCESS")
			//hex.Decode(stripMessDec, stripMess)
			//ioutil.WriteFile(filename, stripMessDec, 0666)

			
		}

		
	}	

}

func main(){
	
	//var i int
	var mainKey string
	var inputFile string
	//var outputFile string

/*	
	arguments := os.Args
	for i = 0; i < len(arguments); i++{
		if arguments[i] == "-k"{
			mainKey = arguments[i+1]
		}

		if arguments[i] == "-i"{
			inputFile = arguments[i+1]
		}

		if arguments[i] == "-o"{
			outputFile = arguments[i+1]
		}
	}
*/
	mainKey = "c026c8432091cabf1eab6213180ccfad3a2c75644b261e74b05b4f77526031e9"
	inputFile = os.Args[1]
//	outputFile = os.Args[2]	
	macKey := make([]byte, 16)
        copy(macKey[:],mainKey[16:32])
	encKey := make([]byte, 16)
	copy(encKey[:],mainKey[0:16])
	macKeyHex := make([]byte, 32)
	hex.Encode(macKeyHex, macKey)
	encKeyHex := make([]byte, 32)
	hex.Encode(encKeyHex, encKey)
        //fmt.Println("\nMac key is: ")
	//fmt.Println(macKey)
	//fmt.Printf("\n Hex Mac Key is: %s",macKeyHex)

	rawCiphertextNew, err := ioutil.ReadFile(inputFile)
	if err != nil{
                panic(err)
        }
 

	//fmt.Println("\n Input Cipher text is: ")
	//fmt.Println(rawCiphertextNew)

	decryptCipher(rawCiphertextNew, encKeyHex, macKeyHex)

}
