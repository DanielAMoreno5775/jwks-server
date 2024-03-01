// Go HTTP router based on a regexp matching function

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"
)

// create global variables to store the RSA key modulus and exponent
var modulusBytes string
var privateExponentBytes string

// structure to store JSON text from the file
type JSONWrapper struct {
	Keys []struct {
		Kty string `json:"Kty"`
		N   string `json:"N"`
		E   string `json:"E"`
		Kid string `json:"Kid"`
		Alg string `json:"Alg"`
		Use string `json:"Use"`
		Exp string `json:"Exp"`
	}
}

type customClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Serve(w http.ResponseWriter, r *http.Request) {
	var h http.Handler

	//get the url that the user entered
	p := r.URL.Path
	//the switch statement will check p (the URL path) vs certain specified URL paths using a regex check AND check to ensure acceptable http method
	switch {
	case match(p, "/") && r.Method == "GET":
		h = get(home)
	case match(p, "/auth") && r.Method == "POST":
		h = post(auth)
	case match(p, "/.well-known/jwks.json") && r.Method == "GET":
		h = get(jwksPage)
	case match(p, "/.well-known/......json") && r.Method == "GET":
		h = get(kidJWK)
	//if a match was not found, return a 405 error code and exit the function
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	//serve up the found page
	h.ServeHTTP(w, r)
}

// reports whether path matches ^regex$, and if it matches,
// assigns any capture groups to the *string or *int vars.
func match(path, pattern string, vars ...interface{}) bool {
	//handles anything in the cache and compiles the passed pattern
	regex := mustCompileCached(pattern)
	//find substring matches
	matches := regex.FindStringSubmatch(path)
	//if 0 or fewer matches, return false
	if len(matches) <= 0 {
		return false
	}
	//iterate through the matches
	for i, match := range matches[1:] {
		//get the piece of data in vars via the value stored in i and use its type for the switch statement
		switch p := vars[i].(type) {
		//if a string pointer, set p equal to the match
		case *string:
			*p = match
		//if an integer pointer, convert match to an int and set p equal to the match
		case *int:
			n, err := strconv.Atoi(match)
			//if there was an error due to the ASCII-to-integer conversion, return false
			if err != nil {
				return false
			}
			*p = n
		//print error message that variables are an incorrect type
		default:
			panic("vars must be *string or *int")
		}
	}
	//a match has been found if this line is ever reached, so return true
	return true
}

// create variables to store the regex and create a mutex lock to prevent issues
var (
	regexen = make(map[string]*regexp.Regexp)
	relock  sync.Mutex
)

// compiles the regex pattern and prevents issues with stuff stored in the cache
func mustCompileCached(pattern string) *regexp.Regexp {
	relock.Lock()
	defer relock.Unlock()

	regex := regexen[pattern]
	if regex == nil {
		regex = regexp.MustCompile("^" + pattern + "$")
		regexen[pattern] = regex
	}
	return regex
}

// allowMethod takes a HandlerFunc and wraps it in a handler that only
// responds if the request method is the given method, otherwise it
// responds with HTTP 405 Method Not Allowed.
func allowMethod(h http.HandlerFunc, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if method != r.Method {
			w.Header().Set("Allow", method)
			http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// get takes a HandlerFunc and wraps it to only allow the GET method
func get(h http.HandlerFunc) http.HandlerFunc {
	return allowMethod(h, "GET")
}

// post takes a HandlerFunc and wraps it to only allow the POST method
func post(h http.HandlerFunc) http.HandlerFunc {
	return allowMethod(h, "POST")
}

// called when a page is gotten, displaying the page for the user
func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "home\n")
}

// called when a page is gotten, displaying the page for the user
func kidJWK(w http.ResponseWriter, r *http.Request) {
	//get the url that the user entered as a string
	u, _ := url.Parse(r.URL.String())
	//get the KID in the path
	fileName := strings.Split(u.Path, "/")
	jwkKid := strings.Split(fileName[2], ".")

	//retrieve specified kid from the database
	sqliteDatabase, err := sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		panic(err)
	}
	defer sqliteDatabase.Close()

	//retrieve the specified row and return it
	statement := "SELECT * FROM keys WHERE kid IS " + jwkKid[0] + " ORDER BY kid"
	row, err := sqliteDatabase.Query(statement)
	if err != nil {
		panic(err)
	}
	defer row.Close()

	for row.Next() { // Iterate and fetch the records from result cursor
		var kid int64
		var key string
		var exp int64
		row.Scan(&kid, &key, &exp)

		//check whether the key is expired
		if exp <= time.Now().Unix() {
			fmt.Println("Expired")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		} else {
			//set the header to JSON so it knows what is being returned
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)

			//assemble the data from the identified key
			jsonJWK := fmt.Sprintf("{\"Kid\":\"%d\", \"Exp\": \"%d\"}", kid, exp)
			//prettify the JSON before printing it
			prettyJSON, err := prettyprint([]byte(jsonJWK))
			if err != nil {
				fmt.Println("Prettify error in kidJWK")
				fmt.Println(err.Error())
				return
			}
			prettyJSONStr := string(prettyJSON)
			fmt.Fprintf(w, "%s\n", prettyJSONStr)
		}
	}
}

// prints out the JSON text in a pretty format with the proper indents
func prettyprint(b []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, b, "", "\t")
	return out.Bytes(), err
}

// called when a page is gotten, displaying the page for the user
func auth(w http.ResponseWriter, r *http.Request) {
	//set the header to JSON so it knows what is being returned
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	//get the url that the user entered as a string
	u, _ := url.Parse(r.URL.String())
	//create a map of the stuff following any ?s
	m, _ := url.ParseQuery(u.RawQuery)

	var token string
	var err error

	//if there weren't any values following the ?, generate a standard JWT
	if len(m) == 0 {
		//generate the token
		token, err = generateJWT(1500000)
		//print an error message and the token to the console
		if err != nil {
			fmt.Println(err)
		}
		//provide the token to the client
		fmt.Fprintf(w, "%s", token)

		//save associated JWK in file since token is not expired
		//extract the kid value from the JW token's header
		arrayOfHeaderPayloadSig := strings.Split(token, ".")
		decodedHeader, _ := base64.StdEncoding.DecodeString(arrayOfHeaderPayloadSig[0])
		indexOfKid := strings.Index(string(decodedHeader[:]), "\"kid\":")
		headerAfterKid := string(decodedHeader[:])[indexOfKid:]
		headerAfterKidSplitByColon := strings.Split(headerAfterKid, ":")
		headerAfterKidSplitByComma := strings.Split(headerAfterKidSplitByColon[1], ",")
		//extract the exp value from the JW token's payload
		decodedPayload, _ := base64.StdEncoding.DecodeString(arrayOfHeaderPayloadSig[1])
		indexOfExp := strings.Index(string(decodedPayload[:]), "\"exp\":")
		payloadAfterExp := string(decodedPayload[:])[indexOfExp:]
		payloadAfterExpSplitByColon := strings.Split(payloadAfterExp, ":")
		payloadAfterExpSplitByComma := strings.Split(payloadAfterExpSplitByColon[1], ",")

		//format all of the data as a JSON string
		jsonJWK := fmt.Sprintf("{\"kid\":%s, \"alg\": \"RS256\", \"kty\": \"RSA\", \"use\": \"sig\", \"n\":\"%s\", \"e\":\"%s\", \"exp\":\"%s\"}", headerAfterKidSplitByComma[0], modulusBytes, privateExponentBytes, payloadAfterExpSplitByComma[0])
		//prettify the JSON text and convert to a string
		prettyJSON, err := prettyprint([]byte(jsonJWK))
		if err != nil {
			fmt.Println("Prettify error in Auth")
			return
		}
		prettyJSONStr := string(prettyJSON)

		//get the current JWKS file
		jsonFile, err := os.ReadFile("./.well-known/jwks.json")
		if err != nil {
			return
		}
		fileStr := string(jsonFile)
		//remove the last bit of the JWKS file
		fileStrTrimmed := fileStr[:len(fileStr)-5]
		//if their is a key already in the set as marked by a }, insert a comma
		if fileStrTrimmed[len(fileStrTrimmed)-1:] == "}" {
			fileStrTrimmed += ","
		}
		//then move the next line
		fileStrTrimmed += "\n"

		//get rid of everything in file currently
		f, err := os.OpenFile("./.well-known/jwks.json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)

		if err != nil {
			return
		}

		//insert into file the altered version of the original contents + the pretty JWK JSON
		fmt.Fprintf(f, "%s%s\n\t]\n}", fileStrTrimmed, prettyJSONStr)

		//close the file
		defer func() {
			if err := f.Close(); err != nil {
				fmt.Printf("failed to close file: %v", err)
			}
		}()
	}
	//if there was one value following the ? AND it was expired=true, generate an expired token
	//based on short-circuit evaluation
	if len(m) == 1 && m["expired"][0] == "true" {
		//generate the token
		token, err = generateJWT(-10)
		//print an error message and the token to the console
		if err != nil {
			fmt.Println(err)
		}
		//provide the token to the client
		fmt.Fprintf(w, "%s", token)
	}
}

// called when a page is gotten, displaying the page for the user and getting the jwks.json file
func jwksPage(w http.ResponseWriter, r *http.Request) {
	//retrieve the json file
	//open the file associated with this URL and do error handling
	fileContent, err := os.Open("./.well-known/jwks.json")
	if err != nil {
		return
	}

	//read the file
	byteResult, _ := io.ReadAll(fileContent)

	//create a variable to store the JSON from the file
	var keys JSONWrapper
	//store the file's contents in the keys variable for standard JSON format
	json.Unmarshal(byteResult, &keys)

	var jsonJWK string
	jsonJWK = "{\"keys\": ["
	for i := 0; i < len(keys.Keys); i++ {
		expDate, _ := strconv.ParseInt(keys.Keys[i].Exp, 10, 64)
		if expDate > time.Now().Unix() {
			jsonJWK += fmt.Sprintf("{\"kid\":\"%s\", \"alg\": \"%s\", \"kty\": \"%s\", \"use\": \"%s\", \"n\":\"%s\", \"e\":\"%s\", \"exp\":\"%s\"},", keys.Keys[i].Kid, keys.Keys[i].Alg, keys.Keys[i].Kty, keys.Keys[i].Use, keys.Keys[i].N, keys.Keys[i].E, keys.Keys[i].Exp)
		}
	}
	jsonJWK = strings.TrimSuffix(jsonJWK, ",")
	jsonJWK += "] }"
	prettyJSON, err := prettyprint([]byte(jsonJWK))
	if err != nil {
		fmt.Println("Prettify error in JWKS page")
		return
	}

	prettyJSONStr := string(prettyJSON)
	fmt.Fprintf(w, "%s\n", prettyJSONStr)

	/*//example code on how to parse out claims from a JWT; unnecessary for Project 1 but may be useful for later
	parsedClaims := ParseToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InJhbmRvbSB1c2VyIG5hbWUiLCJleHAiOjE3MDcyNTUxNzUsImlhdCI6MTcwNzI1NTE3NSwiaXNzIjoibXkgd2Vic2l0ZSBuYW1lIGhlcmUifQ.2_RYleRvteJpU2I3ugWALmaT1Mle79eZ14rGVophGq4DkrkqfoBCpx16eInzrpdlI7kxfyx4yGhc634etfjd83dBMS51OyWMOMwXIu0PsxJlojFEpt_sikcyRWciG2gjC2-oeCcnoTS8h5Dy3wqqJECPEaprtPmi3AlikOhNg9bbjbgiXFLgj6c5k4P60E3NCKQ24lPmLm3HkTnPAHxM35tyzGpGKhNXJGtPCcnqhfkeRv9mzFxn4KRJzzuda68YlbpWUEYCy9ef4az7RAFWWgpinj4Fg407oYou0YRaP1VVR2nVCcbahsM0h3YufxfYfEkdl5_ym1BsohEH_qNrnA")
	jsonClaims := fmt.Sprintf("{ \"username\": \"%s\", \"exp\": %d, \"iat\": %d, \"iss\": \"%s\"}", parsedClaims.Username, parsedClaims.StandardClaims.ExpiresAt, parsedClaims.StandardClaims.IssuedAt, parsedClaims.StandardClaims.Issuer)
	prettyJSON, _ := prettyprint([]byte(jsonClaims))
	fmt.Fprintf(w, "%s", prettyJSON)*/

	/*//retrieve the database
	sqliteDatabase, err := sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		panic(err)
	}
	defer sqliteDatabase.Close()

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
		var alg string
		var kty string
		var use string
		var n string
		var e string
		row.Scan(&kid, &key, &exp, &alg, &kty, &use, &n, &e)
		fmt.Println(kid)

		//check whether the key is expired
		if exp >= (time.Now().Unix() - 5) {
			//assemble the data from the identified key
			jsonJWK += fmt.Sprintf("{\"kid\":\"%d\", \"alg\": \"%s\", \"kty\": \"%s\", \"use\": \"%s\", \"n\":\"%s\", \"e\":\"%s\", \"exp\":\"%d\"},", kid, alg, kty, use, n, e, exp)
		}
	}

	//handle trailing commas and close up the JSON
	jsonJWK = strings.TrimSuffix(jsonJWK, ",")
	jsonJWK += "] }"

	prettyJSON, err := prettyprint([]byte(jsonJWK))
	if err != nil {
		fmt.Println("Prettify error in JWKS page")
		return
	}

	//print the results
	prettyJSONStr := string(prettyJSON)
	fmt.Fprintf(w, "%s\n", prettyJSONStr)*/
}

// this function returns either an error or a signed JWSON Web Token
// if expTime is negative, then token has expired; otherwise, it will expire in passed hours
// creates a new RSA key that will be used for this token
func generateJWT(expTime int) (string, error) {
	//store the size of the RSA key
	bitSize := 2048

	//generate an RSA key and handle any errors
	key, _ := rsa.GenerateKey(rand.Reader, bitSize)

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
	pub := key.Public()

	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	var claims customClaims
	//set token expiration time and claims
	expirationNow := time.Now().Unix()
	expirationLater := time.Now().Add(time.Duration(expTime) * time.Hour).Unix()
	if expTime > 0 {
		claims = customClaims{
			Username: "random user name",
			StandardClaims: jwt.StandardClaims{
				IssuedAt:  expirationNow,
				ExpiresAt: expirationLater,
				Issuer:    "my website name here",
			},
		}
	} else {
		claims = customClaims{
			Username: "random user name",
			StandardClaims: jwt.StandardClaims{
				IssuedAt:  expirationNow,
				ExpiresAt: expirationNow,
				Issuer:    "my website name here",
			},
		}
	}

	//open the database
	sqliteDatabase, err := sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		panic(err)
	}
	defer sqliteDatabase.Close()

	//retrieve the last autoincremented index
	row, _ := sqliteDatabase.Query("select seq from sqlite_sequence where name='keys'")
	defer row.Close()
	var rowID int
	for row.Next() {
		row.Scan(&rowID)
	}

	//create the SQL statement
	insertJWKSQL := `INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)`

	//prepare the SQL statement to prevent injections
	statement, err := sqliteDatabase.Prepare(insertJWKSQL)
	if err != nil {
		panic(err.Error)
	}

	//execute the insertion based on the expiration
	if expTime > 0 {
		statement.Exec(rowID, pubPEM, expirationLater)
	} else {
		statement.Exec(rowID, pubPEM, expirationNow)
	}

	//create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	//set token's kid in header based on whether it is expired
	//if not expired, give it a proper kid
	if expTime > 0 {
		token.Header["kid"] = fmt.Sprintf("%x", rowID)
	} else {
		token.Header["kid"] = fmt.Sprintf("%x", rowID)
	}

	//sign token with RSA private key
	signedToken, err := token.SignedString(key)

	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// retrieve claims from the passedToken
// unneeded for Project 1 but included in case it is needed for later
func ParseToken(passedToken string) (*customClaims, error) {
	parsedToken, _ := jwt.ParseWithClaims(passedToken, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return nil, errors.New("error parsing token claims")
	})

	return parsedToken.Claims.(*customClaims), nil
}

// returns a boolean value whether a file exists
func checkFileExists(filePath string) bool {
	_, error := os.Stat(filePath)
	return !errors.Is(error, os.ErrNotExist)
}
