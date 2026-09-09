package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		wantKey string
		wantErr string // empty string means "expect no error"
	}{
		"valid api key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
			wantErr: "",
		},
		"missing authorization header": {
			headers: http.Header{},
			wantKey: "",
			wantErr: "no authorization header included",
		},
		"wrong scheme (not ApiKey)": {
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			wantKey: "",
			wantErr: "malformed authorization header",
		},
		"missing key after scheme": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: "malformed authorization header",
		},
	}

	for name, tc := range tests {
		tc := tc // capture range variable
		t.Run(name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tc.headers)

			if gotKey != tc.wantKey {
				t.Errorf("key: got %q, want %q", gotKey, tc.wantKey)
			}

			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("expected no error, got: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("expected error %q, got nil", tc.wantErr)
			case tc.wantErr != "" && err != nil && err.Error() != tc.wantErr:
				t.Errorf("expected error %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}
