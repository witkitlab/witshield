package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeStaticFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func staticResponse(handler http.Handler, method, target string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(method, target, nil))
	return response
}

func TestStaticHandlerPreservesResourcesAndSPA(t *testing.T) {
	root := t.TempDir()
	const index = "<!doctype html><title>test application</title>"
	const css = "body { color: navy; }"
	writeStaticFixture(t, filepath.Join(root, "index.html"), index)
	writeStaticFixture(t, filepath.Join(root, "assets", "app.css"), css)
	if err := os.Symlink("assets/app.css", filepath.Join(root, "style.css")); err != nil {
		t.Fatal(err)
	}
	handler := (&Server{webDir: root}).staticHandler()
	for _, tc := range []struct {
		name, method, target, contentType, body string
	}{
		{"root", http.MethodGet, "/", "text/html", index},
		{"SPA route", http.MethodGet, "/devices/detail", "text/html", index},
		{"SPA route with trailing slash", http.MethodGet, "/devices/detail/", "text/html", index},
		{"directory SPA fallback", http.MethodGet, "/assets", "text/html", index},
		{"stylesheet", http.MethodGet, "/assets/app.css?v=1", "text/css", css},
		{"in-root symlink", http.MethodGet, "/style.css", "text/css", css},
		{"HEAD resource", http.MethodHead, "/assets/app.css", "text/css", ""},
		{"HEAD SPA", http.MethodHead, "/devices/detail", "text/html", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := staticResponse(handler, tc.method, tc.target)
			if response.Code != http.StatusOK || response.Body.String() != tc.body || !strings.HasPrefix(response.Header().Get("Content-Type"), tc.contentType) {
				t.Fatalf("status=%d type=%q body=%q", response.Code, response.Header().Get("Content-Type"), response.Body.String())
			}
			if tc.method == http.MethodHead && response.Header().Get("Content-Length") == "" {
				t.Fatal("HEAD response lost content length")
			}
		})
	}
	for _, target := range []string{"/index.html", "/missing/index.html"} {
		redirect := staticResponse(handler, http.MethodGet, target)
		if redirect.Code != http.StatusMovedPermanently || redirect.Header().Get("Location") != "./" {
			t.Fatalf("index redirect %s: status=%d location=%q", target, redirect.Code, redirect.Header().Get("Location"))
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/assets/app.css", nil)
	request.Header.Set("Range", "bytes=0-3")
	partial := httptest.NewRecorder()
	handler.ServeHTTP(partial, request)
	if partial.Code != http.StatusPartialContent || partial.Body.String() != css[:4] {
		t.Fatalf("range response: status=%d body=%q", partial.Code, partial.Body.String())
	}
}

func TestStaticHandlerRejectsAPIPrefixesAndOtherMethods(t *testing.T) {
	root := t.TempDir()
	writeStaticFixture(t, filepath.Join(root, "index.html"), "test application")
	handler := (&Server{webDir: root}).staticHandler()
	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/api/missing", http.StatusNotFound},
		{http.MethodGet, "/agent/missing", http.StatusNotFound},
		{http.MethodPost, "/api/missing", http.StatusNotFound},
		{http.MethodPost, "/", http.StatusMethodNotAllowed},
		{http.MethodPut, "/assets/app.css", http.StatusMethodNotAllowed},
	} {
		response := staticResponse(handler, tc.method, tc.target)
		if response.Code != tc.status || strings.Contains(response.Body.String(), "test application") {
			t.Fatalf("%s %s: status=%d body=%q", tc.method, tc.target, response.Code, response.Body.String())
		}
	}
}

func TestStaticHandlerDoesNotReadOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "web")
	const outside = "OUTSIDE-STATIC-ROOT-TEST-DATA"
	writeStaticFixture(t, filepath.Join(root, "index.html"), "test application")
	writeStaticFixture(t, filepath.Join(parent, "outside.txt"), outside)
	writeStaticFixture(t, filepath.Join(parent, "outside-dir", "secret.txt"), outside)
	for name, target := range map[string]string{
		"absolute.txt": filepath.Join(parent, "outside.txt"),
		"relative.txt": "../outside.txt",
		"outside-dir":  "../outside-dir",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	handler := (&Server{webDir: root}).staticHandler()
	for _, target := range []string{
		"/absolute.txt", "/relative.txt", "/outside-dir/secret.txt",
		"/../outside.txt", "/%2e%2e/outside.txt", "/assets/%2e%2e/%2e%2e/outside.txt",
		"/..%2foutside.txt", "/..%5coutside.txt", "/assets%5c..%5coutside.txt",
		"//../outside.txt", "/%252e%252e/outside.txt", "/..%00/outside.txt",
	} {
		t.Run(target, func(t *testing.T) {
			response := staticResponse(handler, http.MethodGet, target)
			if strings.Contains(response.Body.String(), outside) {
				t.Fatalf("outside test file was served for %q", target)
			}
			if response.Code != http.StatusOK && response.Code != http.StatusNotFound {
				t.Fatalf("unexpected response status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
	if err := os.Remove(filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside.txt", filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/", "/devices/detail", "/index.html"} {
		response := staticResponse(handler, http.MethodGet, target)
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), outside) {
			t.Fatalf("outside SPA index %s: status=%d body=%q", target, response.Code, response.Body.String())
		}
	}
}

func TestStaticHandlerMissingRootAndIndex(t *testing.T) {
	root := t.TempDir()
	writeStaticFixture(t, filepath.Join(root, "asset.txt"), "inside asset")
	for _, directory := range []string{"", filepath.Join(root, "missing"), root} {
		handler := (&Server{webDir: directory}).staticHandler()
		response := staticResponse(handler, http.MethodGet, "/devices/detail")
		if response.Code != http.StatusNotFound {
			t.Fatalf("root %q: status=%d body=%q", directory, response.Code, response.Body.String())
		}
	}
	response := staticResponse((&Server{webDir: root}).staticHandler(), http.MethodGet, "/asset.txt")
	if response.Code != http.StatusOK || response.Body.String() != "inside asset" {
		t.Fatalf("existing asset without SPA index: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestStaticHandlerClosesRequestFileDescriptors(t *testing.T) {
	root := t.TempDir()
	writeStaticFixture(t, filepath.Join(root, "index.html"), "test application")
	writeStaticFixture(t, filepath.Join(root, "asset.txt"), "inside asset")
	handler := (&Server{webDir: root}).staticHandler()
	staticResponse(handler, http.MethodGet, "/asset.txt")
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("file descriptor inspection requires procfs")
	}
	for range 64 {
		staticResponse(handler, http.MethodGet, "/asset.txt")
		staticResponse(handler, http.MethodGet, "/devices/detail")
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before)+4 {
		t.Fatalf("repeated static requests leaked descriptors: before=%d after=%d", len(before), len(after))
	}
}
