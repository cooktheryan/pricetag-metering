package dashboard

import (
	"bytes"
	_ "embed"
)

//go:embed session-view-dialog.html
var sessionViewDialog []byte

//go:embed session-confirm.html
var SessionConfirmation string

// WithSessionDialog adds the same confirmation component to managed dashboards.
// The server remains responsible for authorization and same-origin POST checks.
func WithSessionDialog(page []byte) []byte {
	end := bytes.LastIndex(page, []byte("</body>"))
	if end < 0 {
		end = bytes.LastIndex(page, []byte("</html>"))
	}
	if end < 0 {
		end = len(page)
	}
	result := make([]byte, 0, len(page)+len(sessionViewDialog))
	result = append(result, page[:end]...)
	result = append(result, sessionViewDialog...)
	return append(result, page[end:]...)
}
