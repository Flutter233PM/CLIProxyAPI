package codex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRefreshTokensWithRetry_NonRetryableOnlyAttemptsOnce(t *testing.T) {
	var calls int32
	auth := &CodexAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				atomic.AddInt32(&calls, 1)
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_grant","code":"refresh_token_reused"}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
	}

	_, err := auth.RefreshTokensWithRetry(context.Background(), "dummy_refresh_token", 3)
	if err == nil {
		t.Fatalf("expected error for non-retryable refresh failure")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "refresh_token_reused") {
		t.Fatalf("expected refresh_token_reused in error, got: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 refresh attempt, got %d", got)
	}
}

func TestNormalizeAuthMetadata_BackfillsCodexCompatibilityFields(t *testing.T) {
	normalized, changed := NormalizeAuthMetadata(map[string]any{
		"type":          "codex",
		"email":         "user@example.com",
		"account_id":    "acc_123",
		"chatgpt_user_id": "user_456",
		"plan_type":     "plus",
		"session_token": "sess_789",
	})
	if !changed {
		t.Fatalf("expected compatibility backfill to report changes")
	}
	idToken, ok := normalized["id_token"].(string)
	if !ok || strings.TrimSpace(idToken) == "" {
		t.Fatalf("expected synthesized id_token, got %#v", normalized["id_token"])
	}
	creds, ok := normalized["credentials"].(map[string]any)
	if !ok {
		t.Fatalf("expected credentials map, got %#v", normalized["credentials"])
	}
	for _, key := range []string{"id_token", "chatgpt_account_id", "chatgpt_user_id", "session_token"} {
		if strings.TrimSpace(stringValue(creds, key)) == "" {
			t.Fatalf("expected credentials.%s to be backfilled", key)
		}
	}
	claims, err := ParseJWTToken(idToken)
	if err != nil {
		t.Fatalf("expected synthesized id_token to parse, got error: %v", err)
	}
	if claims.GetAccountID() != "acc_123" {
		t.Fatalf("expected account id acc_123, got %q", claims.GetAccountID())
	}
	if claims.GetChatgptUserID() != "user_456" {
		t.Fatalf("expected user id user_456, got %q", claims.GetChatgptUserID())
	}
	if claims.GetPlanType() != "plus" {
		t.Fatalf("expected plan type plus, got %q", claims.GetPlanType())
	}
	payload, err := decodeJWTPayload(idToken)
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if payload[codexFlatAccountIDClaim] != "acc_123" {
		t.Fatalf("expected flat account id claim, got %#v", payload[codexFlatAccountIDClaim])
	}
	if payload[codexFlatUserIDClaim] != "user_456" {
		t.Fatalf("expected flat user id claim, got %#v", payload[codexFlatUserIDClaim])
	}
	if payload[codexFlatPlanTypeClaim] != "plus" {
		t.Fatalf("expected flat plan type claim, got %#v", payload[codexFlatPlanTypeClaim])
	}
}

func decodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, io.ErrUnexpectedEOF
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}
