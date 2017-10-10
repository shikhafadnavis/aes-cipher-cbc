// Implements Padding Oracle Attack on AES-128 in CBC mode
// This program serves as a tool that accepts a ciphertext and calls the decryption program to perform the decryption with a hardcoded key.
// In return, the decryption program returns one of these messages:
// 1. SUCCESS  2. INVALID MAC   3. INVALID PADDING

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
var j int
var x int
intermediateBlock := make([]byte, 16)
plainBlock := make([]byte, 16)
var z1 int
//var z2 int


cipherBuf, errRead := ioutil.ReadFile(filename)
if errRead != nil{
	panic(errRead)
}
cipherBufCopy := cipherBuf

fmt.Printf("\nOriginal Cipher text: %x", cipherBuf)
cipherBufLen := len(cipherBuf)
fmt.Println("\n Length of original Ciphertext is: ", cipherBufLen)


// Start modifying Buffer for last byte

//rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-17])
//fmt.Printf("\n%x", cipherBufCopy)
//fmt.Printf("\n After these changes, the original buffer is: %x", cipherBuf )
for j = 0; j < 16; j++{

	//Set previous bytes for the right padding
	for x = 0; x < j; x++{
		cipherBufCopy[cipherBufLen-17-x] = intermediateBlock[15-x] ^ byte(j+1) 
	}

	//Set the attack Byte
	for i = 0; i <= 255; i++{
		//rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-17])
		cipherBufCopy[cipherBufLen-17-j] = byte(i) //^ cipherBufCopy[cipherBufLen-17] ^ byte(0x01)
	

		ioutil.WriteFile("modifynew.txt", cipherBufCopy, 0666)

		out, err := exec.Command("./decrypt-test","modifynew.txt").Output()
		if err != nil{
        		fmt.Println(err)
			os.Exit(-1)
		}
		//fmt.Printf("%s",out)
	
		if string(out[len(out)-2]) == "C" || string(out[len(out)-2]) == "S"{
			fmt.Println(string(out))
			fmt.Println("\nAttack Byte Found")
			z1 = i
			break
		}

	//	fmt.Println("\n", string(out))

	}


	//fmt.Printf("\nModeified Ciphertext is: %x", cipherBufCopy)

	fmt.Println("\n Value of modifiedbyte in Cipher is: ", z1)

	cipherBufOrig, errOrig := ioutil.ReadFile(filename)
	if errOrig!=nil{
		panic(errOrig)
	}

	//fmt.Printf("\nRe-Read from file, the cipher is: %x", cipherBufOrig)

	// Calculating Real Plaintext Byte

	intermediateBlock[15-j] = byte(z1) ^ byte(j+1)
	fmt.Printf("\nintermediate byte is%x", intermediateBlock[15-j])
	plainBlock[15-j] = intermediateBlock[15-j] ^ cipherBufOrig[cipherBufLen-17-j]

	fmt.Printf("\nPlainblock this byte is: %x", plainBlock[15-j])

}

fmt.Printf("Plain block is: %x", plainBlock)



} 

