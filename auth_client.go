package steam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

const (
	steamAPIBase = "https://api.steampowered.com"
)

// AuthenticationClient handles new Steam authentication protocol via HTTPS API
type AuthenticationClient struct {
	httpClient *http.Client
}

// NewAuthenticationClient creates a new authentication client
func NewAuthenticationClient() *AuthenticationClient {
	return &AuthenticationClient{
		httpClient: &http.Client{
			Timeout: 60 * time.Second, // Increased timeout
		},
	}
}

// apiResponse represents a generic API response
type apiResponse struct {
	Response json.RawMessage `json:"response"`
}

// structToURLValues converts a struct to url.Values using JSON tags
func structToURLValues(data interface{}) url.Values {
	values := url.Values{}

	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)

		// Get JSON tag name
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}

		// Remove omitempty and other options
		tagName := strings.Split(jsonTag, ",")[0]

		// Skip zero values for omitempty fields
		if strings.Contains(jsonTag, "omitempty") && value.IsZero() {
			continue
		}

		// Convert value to string
		var strValue string
		switch value.Kind() {
		case reflect.String:
			strValue = value.String()
		case reflect.Int, reflect.Int32, reflect.Int64:
			strValue = fmt.Sprintf("%d", value.Int())
		case reflect.Bool:
			strValue = fmt.Sprintf("%t", value.Bool())
		case reflect.Float32, reflect.Float64:
			strValue = fmt.Sprintf("%f", value.Float())
		case reflect.Ptr:
			if !value.IsNil() {
				strValue = fmt.Sprintf("%v", value.Elem().Interface())
			}
		case reflect.Struct:
			// For nested structs, marshal to JSON
			jsonBytes, _ := json.Marshal(value.Interface())
			strValue = string(jsonBytes)
		default:
			strValue = fmt.Sprintf("%v", value.Interface())
		}

		if strValue != "" {
			values.Set(tagName, strValue)
		}
	}

	return values
}

// callAPI makes an HTTP request to Steam Web API
func (ac *AuthenticationClient) callAPI(service, method string, version int, reqData interface{}, respData interface{}, useGET bool) error {
	apiURL := fmt.Sprintf("%s/%s/%s/v%d/", steamAPIBase, service, method, version)

	var req *http.Request
	var err error

	if useGET {
		// For GET requests, append query parameters to URL
		formData := structToURLValues(reqData)
		if len(formData) > 0 {
			apiURL += "?" + formData.Encode()
		}
		fmt.Printf("DEBUG: GET %s\n", apiURL)
		req, err = http.NewRequest("GET", apiURL, nil)
	} else {
		// For POST requests, send as JSON in body
		jsonData, err := json.Marshal(reqData)
		if err != nil {
			return fmt.Errorf("failed to marshal request data: %w", err)
		}
		fmt.Printf("DEBUG: POST %s\nJSON: %s\n", apiURL, string(jsonData))
		req, err = http.NewRequest("POST", apiURL, bytes.NewReader(jsonData))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "go-steam")

	// Send request
	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	fmt.Printf("DEBUG: Response status: %d\n", resp.StatusCode)
	fmt.Printf("DEBUG: Response body: %s\n", string(body))

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response wrapper
	var apiResp apiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return fmt.Errorf("failed to unmarshal response wrapper: %w", err)
	}

	// Parse actual response data
	if err := json.Unmarshal(apiResp.Response, respData); err != nil {
		return fmt.Errorf("failed to unmarshal response data: %w", err)
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetPasswordRSAPublicKeyRequest represents the request for getting RSA public key
type GetPasswordRSAPublicKeyRequest struct {
	AccountName string `json:"account_name"`
}

// GetPasswordRSAPublicKeyResponse represents the response with RSA public key
type GetPasswordRSAPublicKeyResponse struct {
	PublicKeyMod       string `json:"publickey_mod"`
	PublicKeyExp       string `json:"publickey_exp"`
	Timestamp          string `json:"timestamp"`
	TokenGID           string `json:"token_gid,omitempty"`
}

// GetPasswordRSAPublicKey fetches the RSA public key for password encryption
func (ac *AuthenticationClient) GetPasswordRSAPublicKey(accountName string) (*GetPasswordRSAPublicKeyResponse, error) {
	req := GetPasswordRSAPublicKeyRequest{
		AccountName: accountName,
	}

	var resp GetPasswordRSAPublicKeyResponse
	err := ac.callAPI("IAuthenticationService", "GetPasswordRSAPublicKey", 1, req, &resp, true) // Use GET
	if err != nil {
		return nil, fmt.Errorf("GetPasswordRSAPublicKey failed: %w", err)
	}

	return &resp, nil
}

// BeginAuthSessionRequest represents the request to begin authentication session
type BeginAuthSessionRequest struct {
	AccountName        string                      `json:"account_name"`
	EncryptedPassword  string                      `json:"encrypted_password"`
	EncryptionTimestamp string                     `json:"encryption_timestamp"`
	RememberLogin      bool                        `json:"remember_login"`
	PlatformType       int32                       `json:"platform_type"`
	Persistence        int32                       `json:"persistence"`
	WebsiteID          string                      `json:"website_id"`
	DeviceDetails      *DeviceDetails              `json:"device_details,omitempty"`
	GuardData          string                      `json:"guard_data,omitempty"`
	Language           int32                       `json:"language,omitempty"`
}

// DeviceDetails represents device information
type DeviceDetails struct {
	DeviceFriendlyName string `json:"device_friendly_name,omitempty"`
	PlatformType       int32  `json:"platform_type,omitempty"`
	OSType             int32  `json:"os_type,omitempty"`
}

// AllowedConfirmation represents an allowed confirmation method
type AllowedConfirmation struct {
	ConfirmationType  int32  `json:"confirmation_type"`
	AssociatedMessage string `json:"associated_message,omitempty"`
}

// BeginAuthSessionResponse represents the response from beginning auth session
type BeginAuthSessionResponse struct {
	ClientID             string                 `json:"client_id"`
	RequestID            string                 `json:"request_id"`
	Interval             float32                `json:"interval"`
	AllowedConfirmations []*AllowedConfirmation `json:"allowed_confirmations,omitempty"`
	SteamID              string                 `json:"steamid,omitempty"`
	WeakToken            string                 `json:"weak_token,omitempty"`
	AgreementSessionURL  string                 `json:"agreement_session_url,omitempty"`
	ExtendedErrorMessage string                 `json:"extended_error_message,omitempty"`
}

// BeginAuthSessionViaCredentials begins a new authentication session with credentials
func (ac *AuthenticationClient) BeginAuthSessionViaCredentials(req *BeginAuthSessionRequest) (*BeginAuthSessionResponse, error) {
	var resp BeginAuthSessionResponse
	err := ac.callAPI("IAuthenticationService", "BeginAuthSessionViaCredentials", 1, req, &resp, false) // Use POST
	if err != nil {
		return nil, fmt.Errorf("BeginAuthSessionViaCredentials failed: %w", err)
	}

	return &resp, nil
}

// PollAuthSessionStatusRequest represents the request to poll auth session status
type PollAuthSessionStatusRequest struct {
	ClientID      string `json:"client_id"`
	RequestID     string `json:"request_id"`
	TokenToRevoke string `json:"token_to_revoke,omitempty"`
}

// PollAuthSessionStatusResponse represents the response from polling auth session
type PollAuthSessionStatusResponse struct {
	NewClientID          string `json:"new_client_id,omitempty"`
	NewChallengeURL      string `json:"new_challenge_url,omitempty"`
	RefreshToken         string `json:"refresh_token,omitempty"`
	AccessToken          string `json:"access_token,omitempty"`
	HadRemoteInteraction bool   `json:"had_remote_interaction,omitempty"`
	AccountName          string `json:"account_name,omitempty"`
	NewGuardData         string `json:"new_guard_data,omitempty"` // This is the MachineAuthToken!
	AgreementSessionURL  string `json:"agreement_session_url,omitempty"`
}

// PollAuthSessionStatus polls the status of an authentication session
func (ac *AuthenticationClient) PollAuthSessionStatus(clientID, requestID string) (*PollAuthSessionStatusResponse, error) {
	req := PollAuthSessionStatusRequest{
		ClientID:  clientID,
		RequestID: requestID,
	}

	var resp PollAuthSessionStatusResponse
	err := ac.callAPI("IAuthenticationService", "PollAuthSessionStatus", 1, req, &resp, false) // Use POST
	if err != nil {
		return nil, fmt.Errorf("PollAuthSessionStatus failed: %w", err)
	}

	return &resp, nil
}

// UpdateAuthSessionRequest represents the request to update auth session with Steam Guard code
type UpdateAuthSessionRequest struct {
	ClientID string `json:"client_id"`
	SteamID  string `json:"steamid"`
	Code     string `json:"code"`
	CodeType int32  `json:"code_type"`
}

// UpdateAuthSessionResponse represents the response from updating auth session
type UpdateAuthSessionResponse struct {
	AgreementSessionURL string `json:"agreement_session_url,omitempty"`
}

// UpdateAuthSessionWithSteamGuardCode updates the auth session with a Steam Guard code
func (ac *AuthenticationClient) UpdateAuthSessionWithSteamGuardCode(req *UpdateAuthSessionRequest) (*UpdateAuthSessionResponse, error) {
	var resp UpdateAuthSessionResponse
	err := ac.callAPI("IAuthenticationService", "UpdateAuthSessionWithSteamGuardCode", 1, req, &resp, false) // Use POST
	if err != nil {
		return nil, fmt.Errorf("UpdateAuthSessionWithSteamGuardCode failed: %w", err)
	}

	return &resp, nil
}
