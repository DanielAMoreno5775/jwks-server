package main

//https://www.codeproject.com/Articles/5261771/Golang-SQLite-Simple-Example

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// set global constant for the port number
const port = ":8080"

func main() { mainActual(os.Stdout, Serve, 360000) }

// takes a writer (stdout normally), a HTTP handler function (Serve normally), and the number of seconds to serve it (100 hours)
func mainActual(w io.Writer, h http.HandlerFunc, timeServed int64) {

	//create a 32-byte AES key for AES-256
	secret := "N1PCdw3M2B1TfJhoaY2mL736p2vCUc47"

	//create an environment variable called NOT_MY_KEY
	os.Setenv("NOT_MY_KEY", secret)

	httpServerExitDone := &sync.WaitGroup{}

	httpServerExitDone.Add(1)
	srv := startHttpServer(httpServerExitDone, h)

	fmt.Fprintf(w, "Server listening on port %s\n", port)

	time.Sleep(time.Duration(timeServed) * time.Second)

	fmt.Fprintf(w, "HTTP server shutting down\n")

	// now shutdown the server gracefully
	if err := srv.Shutdown(context.TODO()); err != nil {
		panic(err) // failure/timeout shutting down the server gracefully
	}

	// wait for goroutine started in startHttpServer() to stop
	httpServerExitDone.Wait()

	fmt.Fprintf(w, "HTTP server exited\n")
}

func startHttpServer(wg *sync.WaitGroup, h http.HandlerFunc) *http.Server {
	//create servemux (or router) to store a mapping between predefined URL paths for app and handlers
	mux := http.NewServeMux()
	//calls the handler function on the servemux
	mux.HandleFunc("/", h)
	//add the defined global constant port variable and the returned value from limit() to the server structure
	srv := &http.Server{Addr: port, Handler: limit(mux)}

	go func() {
		// let main know clean up is finished
		defer wg.Done()

		// always returns error. ErrServerClosed on graceful close
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// unexpected error. port in use?
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// returning reference so caller can call Shutdown()
	return srv
}
