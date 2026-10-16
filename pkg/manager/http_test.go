// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/testutil"
)

func TestHttpTemplates(t *testing.T) {
	for i, typ := range templTypes {
		t.Run(fmt.Sprintf("%v_%T", i, typ.data), func(t *testing.T) {
			data := testutil.RandValue(t, typ.data)
			if err := typ.templ.Execute(io.Discard, data); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHttpDirectTemplatesBeforeFuzzer(t *testing.T) {
	serv := &HTTPServer{Cfg: &mgrconfig.Config{IsDirect: true}}
	w := httptest.NewRecorder()
	serv.httpTemplates(w, httptest.NewRequest(http.MethodGet, "/templates", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Fuzzer 尚未初始化") {
		t.Fatalf("unexpected templates response: status=%d body=%q", w.Code, w.Body.String())
	}

	serv.Cfg.IsDirect = false
	w = httptest.NewRecorder()
	serv.httpTemplates(w, httptest.NewRequest(http.MethodGet, "/templates", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("non-direct templates status=%d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestLocalRedirectURL(t *testing.T) {
	tests := map[string]string{
		"/stats?x=1":           "/stats?x=1",
		"/":                    "/",
		"https://evil.example": "/",
		"//evil.example":       "/",
		"///evil.example":      "/",
		"/\\evil.example":      "/",
		"javascript:alert(1)":  "/",
	}
	for in, want := range tests {
		if got := localRedirectURL(in); got != want {
			t.Errorf("localRedirectURL(%q) = %q, want %q", in, got, want)
		}
	}
}
