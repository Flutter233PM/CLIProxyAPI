package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestExtractAccessToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata map[string]any
		expected string
	}{
		{
			"antigravity top-level access_token",
			map[string]any{"access_token": "tok-abc"},
			"tok-abc",
		},
		{
			"gemini nested token.access_token",
			map[string]any{
				"token": map[string]any{"access_token": "tok-nested"},
			},
			"tok-nested",
		},
		{
			"top-level takes precedence over nested",
			map[string]any{
				"access_token": "tok-top",
				"token":        map[string]any{"access_token": "tok-nested"},
			},
			"tok-top",
		},
		{
			"empty metadata",
			map[string]any{},
			"",
		},
		{
			"whitespace-only access_token",
			map[string]any{"access_token": "   "},
			"",
		},
		{
			"wrong type access_token",
			map[string]any{"access_token": 12345},
			"",
		},
		{
			"token is not a map",
			map[string]any{"token": "not-a-map"},
			"",
		},
		{
			"nested whitespace-only",
			map[string]any{
				"token": map[string]any{"access_token": "  "},
			},
			"",
		},
		{
			"fallback to nested when top-level empty",
			map[string]any{
				"access_token": "",
				"token":        map[string]any{"access_token": "tok-fallback"},
			},
			"tok-fallback",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractAccessToken(tt.metadata)
			if got != tt.expected {
				t.Errorf("extractAccessToken() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFileTokenStoreSave_NormalizesCodexMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	auth := &cliproxyauth.Auth{
		ID:       "codex.json",
		FileName: "codex.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type":            "codex",
			"email":           "user@example.com",
			"account_id":      "acc_123",
			"chatgpt_user_id": "user_456",
			"plan_type":       "plus",
			"session_token":   "sess_789",
		},
	}

	path, err := store.Save(context.Background(), auth)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if path == "" {
		t.Fatalf("Save() returned empty path")
	}

	stored := readJSONMap(t, path)
	assertNormalizedCodexMetadata(t, stored)
	assertNormalizedCodexMetadata(t, auth.Metadata)
}

func TestFileTokenStoreReadAuthFile_MigratesCodexCompatibility(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "legacy-codex.json")
	legacy := []byte(`{"type":"codex","email":"legacy@example.com","account_id":"acc_legacy","chatgpt_user_id":"user_legacy","plan_type":"plus","session_token":"sess_legacy"}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatalf("failed to seed legacy codex auth file: %v", err)
	}

	store := NewFileTokenStore()
	auth, err := store.readAuthFile(path, dir)
	if err != nil {
		t.Fatalf("readAuthFile() error = %v", err)
	}
	if auth == nil {
		t.Fatalf("expected auth to be returned")
	}
	assertNormalizedCodexMetadata(t, auth.Metadata)

	stored := readJSONMap(t, path)
	assertNormalizedCodexMetadata(t, stored)
}

func readJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("failed to decode %s: %v", path, err)
	}
	return out
}

func assertNormalizedCodexMetadata(t *testing.T, metadata map[string]any) {
	t.Helper()
	if metadata == nil {
		t.Fatalf("expected metadata map")
	}
	if got, _ := metadata["id_token"].(string); got == "" {
		t.Fatalf("expected top-level id_token to be backfilled")
	}
	if got, _ := metadata["chatgpt_account_id"].(string); got != "acc_123" && got != "acc_legacy" {
		t.Fatalf("expected chatgpt_account_id to be backfilled, got %q", got)
	}
	if got, _ := metadata["chatgpt_user_id"].(string); got == "" {
		t.Fatalf("expected chatgpt_user_id to be preserved")
	}
	if got, _ := metadata["session_token"].(string); got == "" {
		t.Fatalf("expected session_token to be preserved")
	}
	credentials, ok := metadata["credentials"].(map[string]any)
	if !ok {
		t.Fatalf("expected credentials map, got %#v", metadata["credentials"])
	}
	if got, _ := credentials["id_token"].(string); got == "" {
		t.Fatalf("expected credentials.id_token to be backfilled")
	}
	if got, _ := credentials["chatgpt_account_id"].(string); got == "" {
		t.Fatalf("expected credentials.chatgpt_account_id to be backfilled")
	}
	if got, _ := credentials["chatgpt_user_id"].(string); got == "" {
		t.Fatalf("expected credentials.chatgpt_user_id to be backfilled")
	}
	if got, _ := credentials["session_token"].(string); got == "" {
		t.Fatalf("expected credentials.session_token to be backfilled")
	}
}
