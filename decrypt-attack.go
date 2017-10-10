// Implements Padding Oracle Attack on AES-128 in CBC mode
// This program serves as a tool that accepts a ciphertext and calls the decryption program to perform the decryption with a hardcoded key.
// In return, the decryption program returns one of these messages:
// 1. SUCCESS  2. INVALID MAC   3. INVALID PAD

package main

import ("fmt"
	"os"
	"os/exec"
	"io/ioutil"
//	"crypto/rand"

)



func main(){

filename := os.Args[2]
var i int

cipherBuf, errRead := ioutil.ReadFile(filename)
if errRead != nil{
	panic(errRead)
}
cipherBufCopy := cipherBuf

fmt.Printf("%x\n", cipherBuf)
cipherBufLen := len(cipherBuf)
fmt.Println("\n Length of original Ciphertext is: ", cipherBufLen)
//successBuf := []byte{83,85,67,67,69,83,83,10}

// Start modifying Buffer for last byte

//newCipherBuf := cipherBuf[cipherBufLen-32:cipherBufLen]
//fmt.Println("\nLength of newCipherBuf is: ", len(newCipherBuf))
//fmt.Printf("At this point, the bytes of concern are: %x\n", newCipherBuf)

//rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-17])
fmt.Printf("\n%x", cipherBufCopy)
//fmt.Printf("\n After these changes, the original buffer is: %x", cipherBuf )
for i = 2; i < 256; i++{
	//rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-17])
	cipherBufCopy[cipherBufLen-17] = byte(i) //^ cipherBufCopy[cipherBufLen-17] ^ byte(0x01)
	//fmt.Printf("\n NewcipherBuf is: %x", newCipherBuf)
	//k := 0
	/*for j := cipherBufLen-32; j <= cipherBufLen-1; j++{
		cipherBufCopy[j] = newCipherBuf[k]
		k++
	}*/
	//fmt.Println("\nModeified Ciphertext is: ", cipherBufCopy)

	errFile := ioutil.WriteFile("modifiedcipher.txt", cipherBufCopy, 0666)
	if errFile != nil{
		panic(errFile)
		
	}
	out, err := exec.Command("./decrypt-test","modifiedcipher.txt").Output()
	if err != nil{
        	fmt.Println(err)
		os.Exit(-1)
	}
	//fmt.Printf("%s",out)
	
	if string(out)=="INVALID MAC\n"{
		fmt.Println("\nSuccess")
		break
	}

//	fmt.Println("\n", string(out))

}

fmt.Printf("\nModeified Ciphertext is: %x", cipherBufCopy)


fmt.Println("\n Value of modifiedbyte in Cipher is: ", i)

cipherBufOrig, errOrig := ioutil.ReadFile(filename)
if errOrig!=nil{
	panic(errOrig)
}

fmt.Printf("\nRe-Read from file, the cipher is: %x", cipherBufOrig)

// Calculating Real Plaintext Byte
intermediateByte := byte(i) ^ 1
fmt.Printf("\n%x", intermediateByte)
plainByte := intermediateByte ^ cipherBufOrig[cipherBufLen-17]

fmt.Println("\n", plainByte)

} 

