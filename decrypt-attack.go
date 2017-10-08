// Implements Padding Oracle Attack on AES-128 in CBC mode
// This program serves as a tool that accepts a ciphertext and calls the decryption program to perform the decryption with a hardcoded key.
// In return, the decryption program returns one of these messages:
// 1. SUCCESS  2. INVALID MAC   3. INVALID PAD

package main

import ("fmt"
	"os"
	"os/exec"
	"io/ioutil"

)



func main(){

filename := os.Args[2]

cipherBuf, errRead := ioutil.ReadFile(filename)
if errRead != nil{
	panic(errRead)
}
fmt.Printf("%x\n", cipherBuf)

cipherBuf[len(cipherBuf)-1] = byte(10)

fmt.Printf("%x\n", cipherBuf)

ioutil.WriteFile("modifiedcipher.txt", cipherBuf, 0666)


out, err := exec.Command("./decrypt-test","modifiedcipher.txt","recovery_trial.txt").Output()

if err != nil{
	panic(err)
}

fmt.Print(string(out))
fmt.Print("\n")





} 
