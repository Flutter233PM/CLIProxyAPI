package codex

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

const (
	codexAuthNamespace           = "https://api.openai.com/auth"
	codexFlatAccountIDClaim      = codexAuthNamespace + ".chatgpt_account_id"
	codexFlatUserIDClaim         = codexAuthNamespace + ".chatgpt_user_id"
	codexFlatPlanTypeClaim       = codexAuthNamespace + ".plan_type"
	codexFlatLegacyPlanTypeClaim = codexAuthNamespace + ".chatgpt_plan_type"
)

// NormalizeAuthJSON backfills Codex auth JSON payloads so both legacy and session-fast-path
// credential formats expose the fields expected by older CPA quota parsers.
func NormalizeAuthJSON(data []byte) ([]byte, map[string]any, bool, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, nil, false, err
	}
	provider, _ := metadata["type"].(string)
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return data, metadata, false, nil
	}
	normalized, changed := NormalizeAuthMetadata(metadata)
	if !changed {
		return data, normalized, false, nil
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, nil, false, err
	}
	return raw, normalized, true, nil
}

// NormalizeAuthMetadata backfills Codex metadata with legacy-compatible top-level and nested
// credentials fields. When a real id_token is missing, it synthesizes a minimal JWT that carries
// the ChatGPT account fields older CPA builds expect.
func NormalizeAuthMetadata(metadata map[string]any) (map[string]any, bool) {
	if metadata == nil {
		return nil, false
	}

	out := cloneMetadataMap(metadata)
	credentials, hadCredentials := cloneNestedMetadata(out["credentials"])

	idToken := pickFirstNonEmpty(
		stringValue(out, "id_token"),
		stringValue(credentials, "id_token"),
	)
	claims, _ := ParseJWTToken(idToken)

	email := pickFirstNonEmpty(
		stringValue(out, "email"),
		stringValue(credentials, "email"),
	)
	if email == "" && claims != nil {
		email = claims.GetUserEmail()
	}

	accountID := pickFirstNonEmpty(
		stringValue(out, "chatgpt_account_id"),
		stringValue(out, "account_id"),
		stringValue(credentials, "chatgpt_account_id"),
		stringValue(credentials, "account_id"),
	)
	if accountID == "" && claims != nil {
		accountID = claims.GetAccountID()
	}

	userID := pickFirstNonEmpty(
		stringValue(out, "chatgpt_user_id"),
		stringValue(credentials, "chatgpt_user_id"),
	)
	if userID == "" && claims != nil {
		userID = claims.GetChatgptUserID()
	}

	planType := pickFirstNonEmpty(
		stringValue(out, "plan_type"),
		stringValue(out, "chatgpt_plan_type"),
		stringValue(credentials, "plan_type"),
		stringValue(credentials, "chatgpt_plan_type"),
	)
	if planType == "" && claims != nil {
		planType = claims.GetPlanType()
	}

	sessionToken := pickFirstNonEmpty(
		stringValue(out, "session_token"),
		stringValue(credentials, "session_token"),
	)

	expiresAt := compatibleTokenExpiry(out, credentials, claims)
	if strings.TrimSpace(idToken) == "" {
		idToken = buildCompatibleIDToken(email, expiresAt.Unix(), accountID, userID, planType)
	}

	changed := false
	changed = setStringIfPresent(out, "id_token", idToken) || changed
	changed = setStringIfPresent(out, "email", email) || changed
	changed = setStringIfPresent(out, "account_id", accountID) || changed
	changed = setStringIfPresent(out, "chatgpt_account_id", accountID) || changed
	changed = setStringIfPresent(out, "chatgpt_user_id", userID) || changed
	changed = setStringIfPresent(out, "plan_type", planType) || changed
	changed = setStringIfPresent(out, "chatgpt_plan_type", planType) || changed
	changed = setStringIfPresent(out, "session_token", sessionToken) || changed

	changed = setStringIfPresent(credentials, "id_token", idToken) || changed
	changed = setStringIfPresent(credentials, "email", email) || changed
	changed = setStringIfPresent(credentials, "account_id", accountID) || changed
	changed = setStringIfPresent(credentials, "chatgpt_account_id", accountID) || changed
	changed = setStringIfPresent(credentials, "chatgpt_user_id", userID) || changed
	changed = setStringIfPresent(credentials, "plan_type", planType) || changed
	changed = setStringIfPresent(credentials, "chatgpt_plan_type", planType) || changed
	changed = setStringIfPresent(credentials, "session_token", sessionToken) || changed

	if hadCredentials || len(credentials) > 0 {
		if !jsonValueEqual(out["credentials"], credentials) {
			out["credentials"] = credentials
			changed = true
		}
	}

	return out, changed
}

// EnrichTokenData normalizes Codex token data and returns a metadata map suitable for persistence.
func EnrichTokenData(tokenData *CodexTokenData, metadata map[string]any) map[string]any {
	merged := cloneMetadataMap(metadata)
	if merged == nil {
		merged = make(map[string]any)
	}
	if tokenData != nil {
		setStringIfPresent(merged, "id_token", tokenData.IDToken)
		setStringIfPresent(merged, "access_token", tokenData.AccessToken)
		setStringIfPresent(merged, "refresh_token", tokenData.RefreshToken)
		setStringIfPresent(merged, "account_id", tokenData.AccountID)
		setStringIfPresent(merged, "chatgpt_account_id", tokenData.ChatgptAccountID)
		setStringIfPresent(merged, "chatgpt_user_id", tokenData.ChatgptUserID)
		setStringIfPresent(merged, "plan_type", tokenData.PlanType)
		setStringIfPresent(merged, "chatgpt_plan_type", tokenData.PlanType)
		setStringIfPresent(merged, "session_token", tokenData.SessionToken)
		setStringIfPresent(merged, "email", tokenData.Email)
		setStringIfPresent(merged, "expired", tokenData.Expire)
	}
	normalized, _ := NormalizeAuthMetadata(merged)
	if tokenData != nil && normalized != nil {
		tokenData.IDToken = stringValue(normalized, "id_token")
		tokenData.AccountID = pickFirstNonEmpty(
			stringValue(normalized, "chatgpt_account_id"),
			stringValue(normalized, "account_id"),
		)
		tokenData.ChatgptAccountID = stringValue(normalized, "chatgpt_account_id")
		tokenData.ChatgptUserID = stringValue(normalized, "chatgpt_user_id")
		tokenData.PlanType = pickFirstNonEmpty(
			stringValue(normalized, "plan_type"),
			stringValue(normalized, "chatgpt_plan_type"),
		)
		tokenData.SessionToken = stringValue(normalized, "session_token")
		tokenData.Email = stringValue(normalized, "email")
	}
	return normalized
}

func buildCompatibleIDToken(email string, expUnix int64, accountID, userID, planType string) string {
	if strings.TrimSpace(accountID) == "" && strings.TrimSpace(userID) == "" && strings.TrimSpace(email) == "" {
		return ""
	}
	if expUnix <= 0 {
		expUnix = time.Now().Add(24 * time.Hour).Unix()
	}
	issuedAt := time.Now().Unix()
	subject := pickFirstNonEmpty(strings.TrimSpace(userID), strings.TrimSpace(accountID), strings.TrimSpace(email))

	header := map[string]any{
		"alg": "none",
		"typ": "JWT",
	}
	payload := map[string]any{
		"email": email,
		"exp":   expUnix,
		"iat":   issuedAt,
		"iss":   "https://auth.openai.com",
		"sub":   subject,
		codexAuthNamespace: map[string]any{
			"chatgpt_account_id": accountID,
			"chatgpt_user_id":    userID,
			"chatgpt_plan_type":  planType,
			"plan_type":          planType,
			"user_id":            userID,
		},
		codexFlatAccountIDClaim:      accountID,
		codexFlatUserIDClaim:         userID,
		codexFlatPlanTypeClaim:       planType,
		codexFlatLegacyPlanTypeClaim: planType,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return ""
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return encodedHeader + "." + encodedPayload + "."
}

func compatibleTokenExpiry(topLevel map[string]any, credentials map[string]any, claims *JWTClaims) time.Time {
	if claims != nil && claims.Exp > 0 {
		return time.Unix(int64(claims.Exp), 0)
	}
	if exp := unixValue(topLevel["exp"]); exp > 0 {
		return time.Unix(exp, 0)
	}
	if exp := unixValue(credentials["exp"]); exp > 0 {
		return time.Unix(exp, 0)
	}
	if ts, ok := parseTimeValue(topLevel["expired"]); ok {
		return ts
	}
	if ts, ok := parseTimeValue(credentials["expired"]); ok {
		return ts
	}
	if ts, ok := parseTimeValue(topLevel["expiry"]); ok {
		return ts
	}
	if ts, ok := parseTimeValue(credentials["expiry"]); ok {
		return ts
	}
	return time.Now().Add(24 * time.Hour)
}

func parseTimeValue(raw any) (time.Time, bool) {
	switch typed := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return time.Time{}, false
		}
		if ts, err := time.Parse(time.RFC3339, trimmed); err == nil {
			return ts, true
		}
		if unix, err := strconv.ParseInt(trimmed, 10, 64); err == nil && unix > 0 {
			return time.Unix(unix, 0), true
		}
	}
	return time.Time{}, false
}

func unixValue(raw any) int64 {
	switch typed := raw.(type) {
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case float32:
		return int64(typed)
	case float64:
		return int64(typed)
	case json.Number:
		if v, err := typed.Int64(); err == nil {
			return v
		}
	case string:
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			if v, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				return v
			}
		}
	}
	return 0
}

func pickFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func stringValue(metadata map[string]any, key string) string {
	if len(metadata) == 0 || strings.TrimSpace(key) == "" {
		return ""
	}
	if value, ok := metadata[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func setStringIfPresent(target map[string]any, key, value string) bool {
	if target == nil || strings.TrimSpace(key) == "" {
		return false
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if current, ok := target[key].(string); ok && strings.TrimSpace(current) == trimmed {
		return false
	}
	target[key] = trimmed
	return true
}

func cloneMetadataMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneNestedMetadata(raw any) (map[string]any, bool) {
	switch typed := raw.(type) {
	case map[string]any:
		return cloneMetadataMap(typed), true
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = value
		}
		return out, true
	default:
		return make(map[string]any), raw != nil
	}
}

func jsonValueEqual(a, b any) bool {
	rawA, errA := json.Marshal(a)
	rawB, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(rawA) == string(rawB)
}
