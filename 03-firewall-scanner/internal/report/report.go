// Package report writes the JSON output.
package report

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/ipd02/cloud-security-engineer-technical-assessment/03-firewall-scanner/internal/model"
)

// Write encodes r as indented JSON followed by a newline. A nil Errors
// slice is written as an empty list. The caller is expected to sort the data.
func Write(w io.Writer, r model.Report) error {
	if r.Errors == nil {
		r.Errors = []model.ProviderError{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}
