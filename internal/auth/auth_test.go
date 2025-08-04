package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if apiKey != "my-secret-key" {
		t.Errorf("expected apiKey to be 'my-secret-key', got '%s'", apiKey)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}
	apiKey, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
	if apiKey != "" {
		t.Errorf("expected apiKey to be empty, got '%s'", apiKey)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer something")
	apiKey, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got %v", err)
	}
	if apiKey != "" {
		t.Errorf("expected apiKey to be empty, got '%s'", apiKey)
	}
}

func TestGetAPIKey_MissingApiKeyValue(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey")
	apiKey, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got %v", err)
	}
	if apiKey != "" {
		t.Errorf("expected apiKey to be empty, got '%s'", apiKey)
	}
}
