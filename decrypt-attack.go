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

for i = 0; i < 256; i++{
	//rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-17])
	cipherBufCopy[cipherBufLen-17] = byte(i)
	//fmt.Printf("\n NewcipherBuf is: %x", newCipherBuf)
	//k := 0
	/*for j := cipherBufLen-32; j <= cipherBufLen-1; j++{
		cipherBufCopy[j] = newCipherBuf[k]
		k++
	}*/
	//fmt.Println("\nModeified Ciphertext is: ", cipherBufCopy)

	ioutil.WriteFile("modifiedcipher.txt", cipherBufCopy, 0666)
	out, err := exec.Command("./decrypt-test","modifiedcipher.txt").Output()
	if err != nil{
        	panic(err)
	}
	
	if string(out)=="SUCCESS\n"{
		fmt.Println("Success")
		break
	}

//	fmt.Println("\n", string(out))

}



/*out, err := exec.Command("./decrypt-test",filename,"recovery_trial.txt").Output()
        if err != nil{
                panic(err)
        }
fmt.Println("\n")
fmt.Println(out)
*/

fmt.Println("\n Value of modifiedbyte in Cipher is: ", i)

// Calculating Real Plaintext Byte
intermediateByte := byte(i) ^ 0x01
plainByte := intermediateByte ^ cipherBufCopy[cipherBufLen-1]

fmt.Printf("\n%x", plainByte)

} 

