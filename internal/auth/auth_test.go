package auth

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidHeader(t *testing.T) {
	wantStr := ""
	wantErr := "no authorization header included"
	testHeader := http.Header{}

	// Test on non-existant field
	http.Header.Set(testHeader, "Nonsense", "What what?")
	gotStr, gotErr := GetAPIKey(testHeader)
	if !reflect.DeepEqual(gotStr, wantStr) {
		t.Fatalf("Expected %v, got %v", wantStr, gotStr)
	}
	assert.EqualError(t, gotErr, wantErr, "Expected no authorization header error, got %v", gotErr)
}

func TestInvalidAuthValue(t *testing.T) {
	wantStr := ""
	wantErr := "malformed authorization header"
	testHeader := http.Header{}

	// Test on invalid split
	http.Header.Set(testHeader, "Authorization", "Apikey123")
	gotStr, gotErr := GetAPIKey(testHeader)
	if !reflect.DeepEqual(gotStr, wantStr) {
		t.Fatalf("Expected %v, got %v", wantStr, gotStr)
	}
	assert.EqualErrorf(t, gotErr, wantErr, "Expected malformed header error, got %v", gotErr)
}

func TestValidAuthValue(t *testing.T) {
	wantStr := "123"
	testHeader := http.Header{}

	//Test on valid split
	http.Header.Set(testHeader, "Authorization", "ApiKey 123")
	gotStr, gotErr := GetAPIKey(testHeader)
	if gotErr != nil {
		t.Fatalf("Got %v, did not expect it", gotErr)
	} else if !reflect.DeepEqual(gotStr, wantStr) {
		t.Fatalf("Got %v, expected %v", gotStr, wantStr)
	}
}
