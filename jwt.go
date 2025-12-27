package steam

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	Sub string   `json:"sub"` // SteamID
	Iss string   `json:"iss"` // Issuer
	Aud []string `json:"aud"` // Audience
}

// DecodeJWT decodes a JWT token without verification (Steam tokens are signed, but we trust them from Steam)
func DecodeJWT(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}

	return &claims, nil
}

// ParseSteamIDFromJWT extracts SteamID from a JWT token's sub claim
func ParseSteamIDFromJWT(token string) (uint64, error) {
	claims, err := DecodeJWT(token)
	if err != nil {
		return 0, err
	}

	// Steam refresh tokens have iss=steam
	if claims.Iss != "steam" {
		return 0, fmt.Errorf("not a Steam refresh token: iss=%s", claims.Iss)
	}

	// Check audience includes "client"
	hasClientAud := false
	for _, aud := range claims.Aud {
		if aud == "client" {
			hasClientAud = true
			break
		}
	}
	if !hasClientAud {
		return 0, fmt.Errorf("refresh token is not valid for Steam client login: aud=%v", claims.Aud)
	}

	// Parse SteamID from sub (format: "steamid:76561198XXXXXXXXX")
	var steamID uint64
	if strings.HasPrefix(claims.Sub, "steamid:") {
		_, err := fmt.Sscanf(claims.Sub, "steamid:%d", &steamID)
		if err != nil {
			return 0, fmt.Errorf("failed to parse SteamID from sub: %w", err)
		}
	} else {
		// Some tokens might just have the steamID directly
		_, err := fmt.Sscanf(claims.Sub, "%d", &steamID)
		if err != nil {
			return 0, fmt.Errorf("failed to parse SteamID from sub: %w", err)
		}
	}

	return steamID, nil
}
