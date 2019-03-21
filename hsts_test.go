package hsts

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gopkg.in/macaron.v1"
	"github.com/stretchr/testify/assert"
)

func Test_HSTSHeaderNoSetting(t *testing.T) {
	recorder := httptest.NewRecorder()

	m := macaron.New()
	m.Use(HSTSHeader(&HSTSOptions{}))

	r, _ := http.NewRequest("GET", "foo", nil)

	m.ServeHTTP(recorder, r)

	hstsHeader := recorder.Header().Get("Strict-Transport-Security")

	assert.Equal(t, hstsHeader, "max-age=0", "base: generated header should match")
}

func Test_HSTSHeaderMaxAge(t *testing.T) {
	recorder := httptest.NewRecorder()

	m := macaron.New()
	m.Use(HSTSHeader(&HSTSOptions{MaxAge: 3600}))

	r, _ := http.NewRequest("GET", "foo", nil)

	m.ServeHTTP(recorder, r)

	hstsHeader := recorder.Header().Get("Strict-Transport-Security")

	assert.Equal(t, hstsHeader, "max-age=3600", "max-age: generated header should match")
}

func Test_HSTSHeaderSubdomain(t *testing.T) {
	recorder := httptest.NewRecorder()

	m := macaron.New()
	m.Use(HSTSHeader(&HSTSOptions{MaxAge: 3600, Subdomains: true}))

	r, _ := http.NewRequest("GET", "foo", nil)

	m.ServeHTTP(recorder, r)

	hstsHeader := recorder.Header().Get("Strict-Transport-Security")

	assert.Equal(t, hstsHeader, "max-age=3600; includeSubDomains", "subdomain: generated header should match")
}

func Test_HSTSHeaderPreload(t *testing.T) {
	recorder := httptest.NewRecorder()

	m := macaron.New()
	m.Use(HSTSHeader(&HSTSOptions{MaxAge: 3600, Preload: true}))

	r, _ := http.NewRequest("GET", "foo", nil)

	m.ServeHTTP(recorder, r)

	hstsHeader := recorder.Header().Get("Strict-Transport-Security")

	assert.Equal(t, hstsHeader, "max-age=3600; preload", "preload: generated header should match")
}

func Test_HSTSHeaderAll(t *testing.T) {
	recorder := httptest.NewRecorder()

	m := macaron.New()
	m.Use(HSTSHeader(&HSTSOptions{MaxAge: 3600, Subdomains: true, Preload: true}))

	r, _ := http.NewRequest("GET", "foo", nil)

	m.ServeHTTP(recorder, r)

	hstsHeader := recorder.Header().Get("Strict-Transport-Security")

	assert.Equal(t, hstsHeader, "max-age=3600; includeSubDomains; preload", "all: generated header should match")
}