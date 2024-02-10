// Test various ways to do HTTP method+path routing in Go

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

// set global constant for the port number
const port = 8080

func main() {
	//if the file doesn't exist, create it
	if !(checkFileExists("./.well-known/jwks.json")) {
		f, _ := os.OpenFile("./.well-known/jwks.json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)

		//insert into file the basic key set format
		fmt.Fprint(f, "{\n\t\"keys\": [\n\n\t]\n}")

		//close the file
		defer func() {
			if err := f.Close(); err != nil {
				fmt.Printf("failed to close file: %v", err)
			}
		}()
	}

	//get the page
	router := http.HandlerFunc(Serve)

	//write in console that the program is ready and listening
	fmt.Printf("listening on port %d\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), router))
}
