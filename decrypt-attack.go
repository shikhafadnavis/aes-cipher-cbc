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
var z1 int
//var z2 int


cipherBuf, errRead := ioutil.ReadFile(filename)
if errRead != nil{
	panic(errRead)
}
cipherBufCopy := cipherBuf

//fmt.Printf("%x\n", cipherBuf)
cipherBufLen := len(cipherBuf)
fmt.Println("\n Length of original Ciphertext is: ", cipherBufLen)


// Start modifying Buffer for last byte

//rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-17])
//fmt.Printf("\n%x", cipherBufCopy)
//fmt.Printf("\n After these changes, the original buffer is: %x", cipherBuf )
for i = 0; i <= 255; i++{
	//rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-17])
	cipherBufCopy[cipherBufLen-17] = byte(i) //^ cipherBufCopy[cipherBufLen-17] ^ byte(0x01)
	//fmt.Printf("\n NewcipherBuf is: %x", newCipherBuf)
	//k := 0
	/*for j := cipherBufLen-32; j <= cipherBufLen-1; j++{
		cipherBufCopy[j] = newCipherBuf[k]
		k++
	}*/
	//fmt.Println("\nModeified Ciphertext is: ", cipherBufCopy)

	ioutil.WriteFile("modifynew.txt", cipherBufCopy, 0666)

	out, err := exec.Command("./decrypt-test","modifynew.txt").Output()
	if err != nil{
        	fmt.Println(err)
		os.Exit(-1)
	}
	//fmt.Printf("%s",out)
	
	//if string(out[len(out)-2])!="G" && i!=74 && i!= 76{
	if string(out) == "INVALID MAC\n"{
		fmt.Println(string(out))
		fmt.Println("\nAttack Byte Found")
		z1 = i
		break
	}

//	fmt.Println("\n", string(out))

}

//fmt.Printf("\nModeified Ciphertext is: %x", cipherBufCopy)

fmt.Println("\n Value of modifiedbyte in Cipher are: ", z1)

cipherBufOrig, errOrig := ioutil.ReadFile(filename)
if errOrig!=nil{
	panic(errOrig)
}

fmt.Printf("\nRe-Read from file, the cipher is: %x", cipherBufOrig)

// Calculating Real Plaintext Byte

intermediateByte := byte(z1) ^ byte(0x01)
fmt.Printf("\nintermediate byte is%x", intermediateByte)
plainByte := intermediateByte ^ cipherBufOrig[cipherBufLen-17]

fmt.Println("\n", plainByte)


////////////////////////////////////////// For the next byte

/*
intermediateByte = byte(0x4b)
cipherLast := intermediateByte ^ byte(0x02)
fmt.Println("\nCipherLast is: ", cipherLast)
cipherBufCopy[cipherBufLen-17] = cipherLast
rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-18])
fmt.Printf("\nCurrently, ciphertext is: %x", cipherBufCopy)
for i = 0; i < 2; i++{
        //rand.Read(cipherBufCopy[cipherBufLen-32:cipherBufLen-17])
        cipherBufCopy[cipherBufLen-18] = byte(i) //^ cipherBufCopy[cipherBufLen-17] ^ byte(0x01)
        //fmt.Printf("\n NewcipherBuf is: %x", newCipherBuf)
        //k := 0
        /*for j := cipherBufLen-32; j <= cipherBufLen-1; j++{
                cipherBufCopy[j] = newCipherBuf[k]
                k++
        }*/
        //fmt.Println("\nModeified Ciphertext is: ", cipherBufCopy)
/*
        ioutil.WriteFile("modifynew.txt", cipherBufCopy, 0666)

        out, err := exec.Command("./decrypt-test","modifynew.txt").Output()
        if err != nil{
                fmt.Println(err)
                os.Exit(-1)
        }
        //fmt.Printf("%s",out)

        if string(out)!="INVALID PADDING\n"{
                fmt.Println(string(out))
                fmt.Println("\nSuccess")
                z2 = i
                break
        }

//      fmt.Println("\n", string(out))

}


fmt.Println("\n z2 is:", z2)

*/

} 

