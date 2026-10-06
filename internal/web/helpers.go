package web

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// maxFormBytes bounds the size of any form submission this UI accepts,
// generous for the forms involved but preventing unbounded body reads.
const maxFormBytes = 1 << 20 // 1 MiB

// parseForm parses r's form body, first limiting how much of it will be
// read into memory.
func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	return r.ParseForm()
}

// idParam parses the {id} URL parameter.
func idParam(r *http.Request) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
}

// parseFormInt64 parses a submitted form field as an int64. Call
// r.ParseForm() before using this.
func parseFormInt64(r *http.Request, field string) (int64, error) {
	return strconv.ParseInt(r.FormValue(field), 10, 64)
}
