package main

import (
	"fmt"
	"net/http"
)

func helloWorld(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Hello world :)\n")
}

func main() {
	http.HandleFunc("/", helloWorld)
	http.ListenAndServe(":8080", nil)
}
