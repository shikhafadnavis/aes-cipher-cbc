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
var k int
var x int
intermediateBlock := make([]byte, 16)
plainBlock := make([]byte, 16)
var z1 int
//var errOrig error
var counter int



extraBytes := 672 


cipherBuf, errRead := ioutil.ReadFile(filename)
if errRead != nil{
	panic(errRead)
}

numBlocks := len(cipherBuf)/16
cipherBufCopy2 := cipherBuf

fmt.Printf("\nOriginal Cipher text: %x", cipherBuf)


cipherBufCopy := make([]byte, len(cipherBuf)+extraBytes)
cipherBufLen := len(cipherBufCopy)

for i= extraBytes; i<cipherBufLen; i++{
	cipherBufCopy[i] = cipherBufCopy2[i-extraBytes]
}

cipherBufOrig := make([]byte, cipherBufLen+extraBytes)
completePlain := make([]byte, cipherBufLen-16) // To reduce the 16 bytes of IV
index := len(completePlain)
fmt.Println("\n Length of original Ciphertext is: ", len(cipherBuf))
//numBlocks := cipherBufLen/16

// Start modifying Buffer for last byte

//rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-17])
//fmt.Printf("\n%x", cipherBufCopy)
//fmt.Printf("\n After these changes, the original buffer is: %x", cipherBuf )

for k = 0; k < numBlocks; k++{

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
	
//		if string(out[len(out)-2]) == "C" || string(out[len(out)-2]) == "S"{
		if string(out) == "INVALID MAC\n" || string(out) == "SUCCESS\n"{
			fmt.Println(string(out))
			fmt.Println("\nAttack Byte Found")
			z1 = i
			break
		}

	//	fmt.Println("\n", string(out))

	} // End of For 0-255


	//fmt.Printf("\nModeified Ciphertext is: %x", cipherBufCopy)

	fmt.Println("\n Value of modifiedbyte in Cipher is: ", z1)

	cipherBufOrig2, errOrig := ioutil.ReadFile(filename)
	if errOrig!=nil{
		fmt.Println(errOrig)
		panic(errOrig)
	}

	//fmt.Printf("\nRe-Read from file, the cipher is: %x", cipherBufOrig)

	// Calculating Real Plaintext Byte
	
	for m:=extraBytes; m<len(cipherBufOrig2)+extraBytes; m++{
		cipherBufOrig[m] = cipherBufOrig2[m-extraBytes]
	}
	intermediateBlock[15-j] = byte(z1) ^ byte(j+1)
	fmt.Printf("\nintermediate byte is: %x", intermediateBlock[15-j])
	plainBlock[15-j] = intermediateBlock[15-j] ^ cipherBufOrig[cipherBufLen-17-j]

	fmt.Printf("\nPlainblock this byte is: %x", plainBlock[15-j])

} // End of for 0-16

fmt.Printf("Plain block is: %x", plainBlock)
//Copy this block to completePlain
p:=0
for counter = index-16; counter < index; counter++{
	completePlain[counter] = plainBlock[p]
	p++
} 

index -= 16

cipherBufCopy = make([]byte, cipherBufLen-16)
cipherBufLen = len(cipherBufCopy)
cipherBufCopy = cipherBufOrig[0:cipherBufLen]
fmt.Println("reached Here")
//fmt.Printf("\n Remaining Length is: %d", cipherBufLen)
//fmt.Printf("\n Remaining CipherBuf is: %x", cipherBufCopy)


} //End of For 0-number of blocks

fmt.Println("\nNumber of blocks decrypted: ", k)
fmt.Printf("\nCompleteplaintext so far is %x", completePlain[extraBytes:len(cipherBuf)+extraBytes-16])



} 

