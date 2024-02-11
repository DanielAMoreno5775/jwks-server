package main

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
	srv := &http.Server{Addr: port}

	//calls the handler function
	http.HandleFunc("/", h)

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
