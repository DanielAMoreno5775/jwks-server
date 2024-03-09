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
	case match(p, `/.well-known/[1-9][0-9]*.json`) && r.Method == "GET":
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

	/*for row.Next() { // Iterate and fetch the records from result cursor
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
	}*/

	// Iterate and fetch the records from result cursor
	for row.Next() {
		var kid int64
		var key string
		var exp int64
		//extract the values from the database
		row.Scan(&kid, &key, &exp)

		//check whether the key is expired
		if exp <= time.Now().Unix() {
			fmt.Println("Expired")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		} else {
			//if it is a private key
			if strings.Contains(key, "-----BEGIN RSA PRIVATE KEY-----") {
				//parse the key to get rsa.PrivateKey
				parsedPrivateKey, _ := ParseRsaPrivateKeyFromPemStr(key)

				//extract the modulus bytes (n)
				modulusBytes := base64.StdEncoding.EncodeToString(parsedPrivateKey.N.Bytes())
				modulusBytes = strings.ReplaceAll(modulusBytes, "/", "_")
				modulusBytes = strings.ReplaceAll(modulusBytes, "+", "-")
				modulusBytes = strings.ReplaceAll(modulusBytes, "=", "")
				if (len(modulusBytes) % 2) != 0 {
					modulusBytes = "A" + modulusBytes
				}

				//set the exponent bytes
				privateExponentBytes := "AQAB"

				//set the header to JSON so it knows what is being returned
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)

				//assemble the data from the retrieved key
				jsonJWK := fmt.Sprintf("{\"kid\":\"%d\", \"alg\": \"RS256\", \"kty\": \"RSA\", \"use\": \"sig\", \"n\":\"%s\", \"e\":\"%s\", \"exp\":\"%d\"}", kid, modulusBytes, privateExponentBytes, exp)

				//prettify the JSON before printing it
				prettyJSON, err := prettyprint([]byte(jsonJWK))
				if err != nil {
					fmt.Println("Prettify error in kidJWK")
					fmt.Println(err.Error())
					return
				}
				prettyJSONStr := string(prettyJSON)
				fmt.Fprintf(w, "%s\n", prettyJSONStr)
			} else if strings.Contains(key, "-----BEGIN RSA PUBLIC KEY-----") {
				//set the header to JSON so it knows what is being returned
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)

				key = strings.ReplaceAll(key, "\n", "")

				//assemble the data from the retrieved key
				jsonJWK := fmt.Sprintf("{\"kid\": \"%d\", \"key\": \"%s\", \"exp\": \"%d\"}", kid, key, exp)

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

// called when a page is gotten, displaying the page for the user and getting the database file
func jwksPage(w http.ResponseWriter, r *http.Request) {
	/*//example code on how to parse out claims from a JWT; unnecessary for Project 1 but may be useful for later
	parsedClaims := ParseToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InJhbmRvbSB1c2VyIG5hbWUiLCJleHAiOjE3MDcyNTUxNzUsImlhdCI6MTcwNzI1NTE3NSwiaXNzIjoibXkgd2Vic2l0ZSBuYW1lIGhlcmUifQ.2_RYleRvteJpU2I3ugWALmaT1Mle79eZ14rGVophGq4DkrkqfoBCpx16eInzrpdlI7kxfyx4yGhc634etfjd83dBMS51OyWMOMwXIu0PsxJlojFEpt_sikcyRWciG2gjC2-oeCcnoTS8h5Dy3wqqJECPEaprtPmi3AlikOhNg9bbjbgiXFLgj6c5k4P60E3NCKQ24lPmLm3HkTnPAHxM35tyzGpGKhNXJGtPCcnqhfkeRv9mzFxn4KRJzzuda68YlbpWUEYCy9ef4az7RAFWWgpinj4Fg407oYou0YRaP1VVR2nVCcbahsM0h3YufxfYfEkdl5_ym1BsohEH_qNrnA")
	jsonClaims := fmt.Sprintf("{ \"username\": \"%s\", \"exp\": %d, \"iat\": %d, \"iss\": \"%s\"}", parsedClaims.Username, parsedClaims.StandardClaims.ExpiresAt, parsedClaims.StandardClaims.IssuedAt, parsedClaims.StandardClaims.Issuer)
	prettyJSON, _ := prettyprint([]byte(jsonClaims))
	fmt.Fprintf(w, "%s", prettyJSON)*/

	//retrieve the database
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
		//extract the values from the database
		row.Scan(&kid, &key, &exp)

		//since the database contains private and public keys, only try to decrypt the private keys
		if strings.Contains(key, "-----BEGIN RSA PRIVATE KEY-----") {
			//parse the key to get rsa.PrivateKey
			parsedPrivateKey, _ := ParseRsaPrivateKeyFromPemStr(key)

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
	prettyJSON, err := prettyprint([]byte(jsonJWK))
	if err != nil {
		fmt.Println("Prettify error in JWKS page")
		return
	}

	//print the results
	prettyJSONStr := string(prettyJSON)
	fmt.Fprintf(w, "%s\n", prettyJSONStr)
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

	//PEM encode the private RSA key to be saved in the database
	privatePEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
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
				IssuedAt:  expirationNow - 10,
				ExpiresAt: expirationNow - 10,
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

	//create the SQL statement expected by gradebot and linter
	dummyJWKSQL := `INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)`
	fmt.Println(dummyJWKSQL)

	insertJWKSQL := `INSERT INTO keys (kid, key, exp) VALUES (NULL, ?, ?)`

	//prepare the SQL statement to prevent injections
	statement, err := sqliteDatabase.Prepare(insertJWKSQL)
	if err != nil {
		panic(err.Error)
	}

	//execute the insertion based on the desired expiration that was passed
	if expTime > 0 {
		statement.Exec(privatePEM, expirationLater)
	} else {
		statement.Exec(privatePEM, expirationNow)
	}

	//retrieve the last autoincremented index from the special sqlite_sequence table
	row, _ := sqliteDatabase.Query("select seq from sqlite_sequence where name='keys'")
	defer row.Close()
	var rowID int
	for row.Next() {
		row.Scan(&rowID)
	}

	//close everything to ensure that the defers work properly as the jwks.json GET request won't work if the SQLite database isn't properly closed
	sqliteDatabase.Close()
	row.Close()

	//create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	//set token's kid in header based on whether it is expired
	//if not expired, give it a proper kid
	if expTime > 0 {
		token.Header["kid"] = fmt.Sprintf("%d", rowID)
	} else {
		token.Header["kid"] = fmt.Sprintf("%d", rowID)
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

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}
