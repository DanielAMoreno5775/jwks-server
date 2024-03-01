package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testType string

func TestMain(m *testing.M) {
	testType = os.Args[len(os.Args)-1]
	os.Exit(m.Run())
}

// uses a variant of other function to test whether the HTTP server is served up properly
func TestHTTPServingFuncsWithServe(t *testing.T) {
	var output bytes.Buffer
	//calls mainActual with a custom output buffer, the standard handler function, and tells it to run for 2 seconds after removing the file
	mainActual(&output, Serve, 1)
	correctString := fmt.Sprintf("Server listening on port %s\nHTTP server shutting down\nHTTP server exited\n", port)
	if output.String() != correctString {
		t.Errorf("Issue with mainActual or startHttpServer as they serve up the HTTP server on port 8080")
	}
}

// function to verify valid JWKs in JWKS.json file
func TestJWKSFile(t *testing.T) {
	//try to open the file and handle any errors
	fileContents, err := os.ReadFile("./.well-known/jwks.json")
	if err != nil {
		t.Errorf("jwks.json file doesn't exist")
	}

	//check whether file exists using written function; since the previous check was passed, this one should pass too
	if !(checkFileExists("./.well-known/jwks.json")) {
		t.Errorf("checkFileExists incorrectly marked jwks.json as missing ")
	}

	//convert the fileContents into a string
	fileString := string(fileContents)

	//check if valid JSON string
	if !isJSON(fileString) {
		t.Errorf("Invalid JSON in jwks.json file")
	}

	//check whether JSON in the file meets the JWKS format
	//create a variable to store the JSON from the file
	var keys JSONWrapper
	//store the file's contents in the keys variable for standard JSON format and create string to store precise string
	json.Unmarshal(fileContents, &keys)
	var jsonJWK string

	//attempt to assemble the string
	jsonJWK = "{\"keys\": ["
	for i := 0; i < len(keys.Keys); i++ {
		//test each value in the key to ensure it exists
		if keys.Keys[i].Kid == "" {
			t.Errorf("Empty KID attribute stored in Key: %d", i)
		} else if keys.Keys[i].Alg == "" {
			t.Errorf("Empty Alg attribute stored in Key: %d", i)
		} else if keys.Keys[i].Kty == "" {
			t.Errorf("Empty Kty attribute stored in Key: %d", i)
		} else if keys.Keys[i].Use == "" {
			t.Errorf("Empty Use attribute stored in Key: %d", i)
		} else if keys.Keys[i].N == "" {
			t.Errorf("Empty N attribute stored in Key: %d", i)
		} else if keys.Keys[i].E == "" {
			t.Errorf("Empty E attribute stored in Key: %d", i)
		} else if keys.Keys[i].Exp == "" {
			t.Errorf("Empty Exp attribute stored in Key: %d", i)
		}

		//try to convert expiration date into int64
		_, err := strconv.ParseInt(keys.Keys[i].Exp, 10, 64)
		//if the expiration date can't be turned into an int64, mark as failure
		if err != nil {
			t.Errorf("Invalid expiration date stored in Key: %d", i)
		}

		jsonJWK += fmt.Sprintf("{\"kid\":\"%s\", \"alg\": \"%s\", \"kty\": \"%s\", \"use\": \"%s\", \"n\":\"%s\", \"e\":\"%s\", \"exp\":\"%s\"},", keys.Keys[i].Kid, keys.Keys[i].Alg, keys.Keys[i].Kty, keys.Keys[i].Use, keys.Keys[i].N, keys.Keys[i].E, keys.Keys[i].Exp)
	}
	jsonJWK = strings.TrimSuffix(jsonJWK, ",")
	jsonJWK += "] }"
	prettyJSON, err := prettyprint([]byte(jsonJWK))
	if err != nil {
		t.Errorf("Invalid JSON in jwks.json file - prettify error")
		return
	}
	_ = prettyJSON
}

// check if valid json
func isJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}

// very quick check to ensure mainActual serves up pages correctly
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"alive": true}`)
}

// test the invalid page message "/invalidpage"
func TestInvalidPage(t *testing.T) {
	//create an HTTP request and recorder
	req := httptest.NewRequest(http.MethodGet, "/invalidpage", nil)
	w := httptest.NewRecorder()

	//call the Serve function, store the results, and defer the closing
	Serve(w, req)
	res := w.Result()
	defer res.Body.Close()

	//try to read the returned page
	data, err := io.ReadAll(res.Body)

	//ensure no errors when sending the GET request
	if err != nil {
		t.Errorf("Error when sending GET request to /invalidpage: %v", err)
	}

	//ensure returned data is "Method Not Allowed"
	if string(data) != "Method Not Allowed\n" {
		t.Errorf("Expected \"Method Not Allowed\n\" for /invalidpage but got %v", string(data))
	}

	//create an HTTP request and recorder
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	w = httptest.NewRecorder()

	//call the Serve function, store the results, and defer the closing
	Serve(w, req)
	res = w.Result()
	defer res.Body.Close()

	//try to read the returned page
	data, _ = io.ReadAll(res.Body)
	if string(data) != "Method Not Allowed\n" {
		t.Errorf("Expected \"Method Not Allowed\n\" for /auth GET but got %v", string(data))
	}
}

// test the default page "/"
func TestHomePage(t *testing.T) {
	//create an HTTP request and recorder
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	//call the Serve function, store the results, and defer the closing
	Serve(w, req)
	res := w.Result()
	defer res.Body.Close()

	//try to read the returned page
	data, err := io.ReadAll(res.Body)

	//ensure no errors when sending the GET request
	if err != nil {
		t.Errorf("Error when sending GET request to /: %v", err)
	}

	//ensure returned data is "home"
	if string(data) != "home\n" {
		t.Errorf("Expected \"home\n\" but got %v", string(data))
	}
}

func TestGetSpecificJWK(t *testing.T) {
	//try to open the file with minimal error checking as most should have been handled earlier
	fileContents, err := os.ReadFile("./.well-known/jwks.json")
	if err != nil {
		t.Errorf("jwks.json file doesn't exist")
	}

	//create a variable to store the JSON from the file
	var keys JSONWrapper
	//store the file's contents in the keys variable for standard JSON format and create string to store precise string
	json.Unmarshal(fileContents, &keys)

	//retrieve the first KID in the file
	jsonJWKKID := keys.Keys[0].Kid
	for len(jsonJWKKID) != 5 {
		jsonJWKKID = "0" + jsonJWKKID
	}
	requestURL := "/.well-known/" + jsonJWKKID + ".json"

	//create an HTTP request and recorder
	req := httptest.NewRequest(http.MethodGet, requestURL, nil)
	w := httptest.NewRecorder()

	//call the Serve function, store the results, and defer the closing
	Serve(w, req)
	res := w.Result()
	defer res.Body.Close()

	//try to read the returned page
	data, err := io.ReadAll(res.Body)

	//ensure no errors when sending the GET request
	if err != nil {
		t.Errorf("Error when sending GET request to /: %v", err)
	}

	//try to prettify retrieved data into valid JSON
	//if the prettify succeeds, assumes valid output due to earlier tests
	prettyJSON, err := prettyprint(data)
	if err != nil {
		t.Errorf("Invalid JSON returned when %s.json is called", jsonJWKKID)
		return
	}
	_ = prettyJSON
}

func TestGetJWKS(t *testing.T) {
	//create an HTTP request and recorder
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	//call the Serve function, store the results, and defer the closing
	Serve(w, req)
	res := w.Result()
	defer res.Body.Close()

	//try to read the returned page
	data, err := io.ReadAll(res.Body)

	//ensure no errors when sending the GET request
	if err != nil {
		t.Errorf("Error when sending GET request to /: %v", err)
	}

	//create a variable to store the JSON from the file
	var keys JSONWrapper
	//store the file's contents in the keys variable for standard JSON format
	json.Unmarshal(data, &keys)

	//assemble strings from unmarshalled JSON data
	var jsonJWK string
	jsonJWK = "{\"keys\": ["
	for i := 0; i < len(keys.Keys); i++ {
		expDate, _ := strconv.ParseInt(keys.Keys[i].Exp, 10, 64)
		if expDate > time.Now().Unix() {
			jsonJWK += fmt.Sprintf("{\"kid\":\"%s\", \"alg\": \"%s\", \"kty\": \"%s\", \"use\": \"%s\", \"n\":\"%s\", \"e\":\"%s\", \"exp\":\"%s\"},", keys.Keys[i].Kid, keys.Keys[i].Alg, keys.Keys[i].Kty, keys.Keys[i].Use, keys.Keys[i].N, keys.Keys[i].E, keys.Keys[i].Exp)
		}
	}
	//remove final comma
	jsonJWK = strings.TrimSuffix(jsonJWK, ",")
	//finish up JSON and prettify it
	jsonJWK += "] }"
	prettyJSON, err := prettyprint([]byte(jsonJWK))
	if err != nil {
		t.Errorf("Prettify error on JWKS page")
		return
	}
	_ = prettyJSON
}

func TestPOSTAuth(t *testing.T) {
	//create an HTTP request and recorder
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()

	//call the Serve function, store the results, and defer the closing
	Serve(w, req)
	res := w.Result()
	defer res.Body.Close()

	//try to read the returned page
	data, err := io.ReadAll(res.Body)

	//ensure no errors when sending the GET request
	if err != nil {
		t.Errorf("Error when sending POST request to: %v", err)
	}

	//try to parse JWT claims
	parsedClaims, err := ParseToken(string(data))
	jsonClaims := fmt.Sprintf("{ \"username\": \"%s\", \"exp\": %d, \"iat\": %d, \"iss\": \"%s\"}", parsedClaims.Username, parsedClaims.StandardClaims.ExpiresAt, parsedClaims.StandardClaims.IssuedAt, parsedClaims.StandardClaims.Issuer)
	if err != nil {
		t.Errorf("Error parsing data from JWKS page: %v", err)
	}
	_ = jsonClaims

}

func TestPOSTAuthExpired(t *testing.T) {
	//create an HTTP request and recorder
	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	w := httptest.NewRecorder()

	//call the Serve function, store the results, and defer the closing
	Serve(w, req)
	res := w.Result()
	defer res.Body.Close()

	//try to read the returned page
	data, err := io.ReadAll(res.Body)

	//ensure no errors when sending the GET request
	if err != nil {
		t.Errorf("Error when sending POST request to: %v", err)
	}

	//try to parse JWT claims
	parsedClaims, err := ParseToken(string(data))
	if err != nil {
		t.Errorf("Error parsing data from JWKS page: %v", err)
	}

	//ensure that the JWT is expired
	if parsedClaims.StandardClaims.ExpiresAt != parsedClaims.StandardClaims.IssuedAt || parsedClaims.StandardClaims.ExpiresAt > time.Now().Unix() {
		t.Errorf("Token isn't expired")
	}
}

func TestAllowMethod(t *testing.T) {
	allowMethod(Serve, "PATCH")
}

func TestRegexMatch(t *testing.T) {
	if !match("test", "test") {
		t.Errorf("Error with match function for test-test")
	}
	if !match("1", "1") {
		t.Errorf("Error with match function for 1-1")
	}
	if match("114364368414896743814584183618", "1") {
		t.Errorf("Error with match function for 114364368414896743814584183618-1")
	}
}
