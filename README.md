# Project 1: JWKS Server

## Running the Server
Open a terminal window in the root directory. Then, enter the following command. The server will remain open for 100 hours or until the user exits it via something like a Keyboard Interrupt.
```
go run main.go route.go
```
If this doesn't work due to CGO being disabled, you can create a .bat file (assuming a Windows computer) with the following lines
```
set CGO_ENABLED=1
go run main.go route.go
```

Accessing a specific kid can be done with the following URL, if it is not expired: http://localhost:8080/.well-known/00014.json

## Test Suite
Open a terminal window in the root directory. Then, enter the following commands in the following order.
```
go test -v ./... -coverprofile profile.out
go tool cover -func profile.out
go tool cover '-html=profile.out' -o testcoverage.html
```

## Fixing a CGO Error
If you see the error of
```
# runtime/cgo
cc1.exe: sorry, unimplemented: 64-bit mode not compiled in
```
perform the following steps (assuming a Windows computer).
 1. Install the tdm-gcc-64 bundle for x86-64
 2. Add the file path to the PATH variable (Example: C:\TDM-GCC-64\bin)
 3. Move that file path to the top of the PATH variable list to prevent conflicts
 4. If the issue persists, alter `go env` to point to that file path

## Screenshots
![Coverage of Custom Test Suite](./Custom-Test-Suite-Screenshot.png)
![Rubric Result of Gradebot Project 1](./Gradebot-Screenshot-Project1.png)
![Rubric Result of Gradebot Project 2](./Gradebot-Screenshot-Project2.png)