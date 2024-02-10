// Test various ways to do HTTP method+path routing in Go

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// set global constant for the port number
const port = 8080

// create a global variable to store the private RSA key
var key *rsa.PrivateKey
var privateKeyBytes []uint8
var keyPEM []uint8
var pub crypto.PublicKey
var pubPEM []byte
var modulusBytes string
var privateExponentBytes string

func main() {
	//get rid of everything in file currently
	f, _ := os.OpenFile("./.well-known/jwks.json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)

	//insert into file the altered version of the original contents + the pretty JWK JSON
	fmt.Fprint(f, "{\n\t\"keys\": [\n\n\t]\n}")

	//close the file
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Printf("failed to close file: %v", err)
		}
	}()

	//store the size of the RSA key
	bitSize := 2048

	//generate an RSA key and handle any errors
	key, _ = rsa.GenerateKey(rand.Reader, bitSize)

	//try to extract the modulus
	modulusBytes = base64.StdEncoding.EncodeToString(key.N.Bytes())
	modulusBytes = strings.ReplaceAll(modulusBytes, "/", "_")
	modulusBytes = strings.ReplaceAll(modulusBytes, "+", "-")
	modulusBytes = strings.ReplaceAll(modulusBytes, "=", "")
	if (len(modulusBytes) % 2) != 0 {
		modulusBytes = "A" + modulusBytes
	}

	//try to extract the exponent
	privateExponentBytes = "AQAB"

	//extract the public key
	pub = key.Public()

	//get the private key bytes after marshalling it according to the X.509 standard
	privateKeyBytes = x509.MarshalPKCS1PrivateKey(key)

	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)

	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	//get the page
	router := http.HandlerFunc(Serve)

	//write in console that the program is ready and listening
	fmt.Printf("listening on port %d\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), router))
}
