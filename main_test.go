package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
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
	//check whether file exists using written function; since the previous check was passed, this one should pass too
	if !(checkFileExists("./totally_not_my_privateKeys.db")) {
		t.Errorf("checkFileExists incorrectly marked the database file as missing ")
	}

	//retrieve the database
	sqliteDatabase, err := sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		panic(err)
	}
	defer sqliteDatabase.Close()

	//check whether the keys table exists
	tableCheckResult, _ := sqliteDatabase.Query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='keys';")
	defer tableCheckResult.Close()
	var tableCheckInt int
	for tableCheckResult.Next() {
		tableCheckResult.Scan(&tableCheckInt)
	}
	if tableCheckInt != 1 {
		t.Errorf("The keys table does not exist")
	}

	//count the number of columns in the table
	colCount, _ := sqliteDatabase.Query("SELECT COUNT(*) FROM PRAGMA_TABLE_INFO('keys')")
	defer colCount.Close()
	var numOfCols int
	for colCount.Next() {
		colCount.Scan(&numOfCols)
	}
	if numOfCols != 3 {
		t.Errorf("Wrong number of fields in keys table")
	}

	//retrieve the specified row and return it
	statement := "SELECT * FROM keys"
	row, err := sqliteDatabase.Query(statement)
	if err != nil {
		panic(err)
	}
	defer row.Close()

	// Iterate and fetch the records from result cursor
	var jsonJWK string
	jsonJWK = "{\"keys\": ["
	for row.Next() {
		var kid int64
		var key string
		var exp int64
		//extract the values from the database
		row.Scan(&kid, &key, &exp)

		//since the database contains private and public keys, only try to decrypt the private keys
		if strings.Contains(key, "-----BEGIN RSA PRIVATE KEY-----") {
			//parse the key to get rsa.PrivateKey
			parsedPrivateKey, err := ParseRsaPrivateKeyFromPemStr(key)
			if err != nil {
				t.Errorf("Error parsing RSA private key from database")
			}

			//extract the modulus bytes (n)
			modulusBytes = base64.StdEncoding.EncodeToString(parsedPrivateKey.N.Bytes())
			modulusBytes = strings.ReplaceAll(modulusBytes, "/", "_")
			modulusBytes = strings.ReplaceAll(modulusBytes, "+", "-")
			modulusBytes = strings.ReplaceAll(modulusBytes, "=", "")
			if (len(modulusBytes) % 2) != 0 {
				modulusBytes = "A" + modulusBytes
			}

			//set the exponent bytes
			privateExponentBytes = "AQAB"

			//if the key is not expired, append it to the JSON string
			if exp > time.Now().Unix() {
				//assemble the data from the retrieved key
				jsonJWK += fmt.Sprintf("{\"kid\":\"%d\", \"alg\": \"RS256\", \"kty\": \"RSA\", \"use\": \"sig\", \"n\":\"%s\", \"e\":\"%s\", \"exp\":\"%d\"},", kid, modulusBytes, privateExponentBytes, exp)
			}
		}
	}

	//handle trailing commas and close up the JSON
	jsonJWK = strings.TrimSuffix(jsonJWK, ",")
	jsonJWK += "] }"

	//prettify the JSON
	_, err = prettyprint([]byte(jsonJWK))
	if err != nil {
		t.Errorf("Prettify error in JWKS page")
		return
	}
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
	//retrieve specified kid from the database
	sqliteDatabase, err := sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		panic(err)
	}
	defer sqliteDatabase.Close()

	//retrieve the specified row and return it
	statement := "SELECT * FROM keys ORDER BY kid"
	row, err := sqliteDatabase.Query(statement)
	if err != nil {
		panic(err)
	}
	defer row.Close()

	// Iterate and fetch the records from result cursor
	var storedPrivateKID int64
	for row.Next() {
		var kid int64
		var key string
		var exp int64
		//extract the values from the database
		row.Scan(&kid, &key, &exp)

		//if the key is not expired, exit the for loop and keep the current kid
		if exp > time.Now().Unix() {
			storedPrivateKID = kid
			break
		}
	}

	requestURL := fmt.Sprintf("/.well-known/%d.json", storedPrivateKID)

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
		t.Errorf("Invalid JSON returned when %d.json is called for Private Key", storedPrivateKID)
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
	//setup the JSON request body
	postBody := map[string]interface{}{
		"username": "MyCoolUsername",
		"password": "password123",
	}
	body, _ := json.Marshal(postBody)

	//create an HTTP request and recorder
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewReader(body))
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
	//setup the JSON request body
	postBody := map[string]interface{}{
		"username": "MyCoolUsername",
		"password": "password123",
	}
	body, _ := json.Marshal(postBody)

	//create an HTTP request and recorder
	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", bytes.NewReader(body))
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

func TestRegister(t *testing.T) {
	randomNum := rand.Intn(10000000)
	name := "testingName_" + strconv.Itoa(randomNum)

	//setup the JSON request body
	postBody := map[string]interface{}{
		"username": name,
		"email":    "MyCoolEmail",
	}
	body, _ := json.Marshal(postBody)

	//create an HTTP request and recorder
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
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

	//try to parse returned JSON to ensure valid format
	prettyJSON, err := prettyprint(data)
	if err != nil {
		t.Errorf("Prettify error on Register page")
		return
	}
	_ = prettyJSON
}

func TestAllowMethod(t *testing.T) {
	allowMethod(Serve, "PATCH")
	allowMethod(kidJWK, "PATCH")
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

func TestParseRsaPrivateKeyFromPemStr(t *testing.T) {
	_, err := ParseRsaPrivateKeyFromPemStr("test")

	if err == nil {
		t.Errorf("ParseRsaPrivateKeyFromPemStr parsed a string that is not an RSA private key")
	}
}
