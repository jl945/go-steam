package steam

import (
	"fmt"
	"strconv"
	"time"
)

// AuthenticationSession represents an active authentication session
type AuthenticationSession struct {
	client    *AuthenticationClient
	clientID  string
	requestID string
	steamID   string
	interval  float32

	// Channel to receive Steam Guard code from user
	steamGuardCodeChan chan string
}

// NewAuthenticationSession creates a new authentication session using the new protocol
func NewAuthenticationSession() *AuthenticationSession {
	return &AuthenticationSession{
		client:             NewAuthenticationClient(),
		steamGuardCodeChan: make(chan string, 1),
	}
}

// LoginWithCredentials performs the complete authentication flow with username and password
func (as *AuthenticationSession) LoginWithCredentials(username, password string, machineAuthToken string) (*LoginResult, error) {
	// Step 1: Get RSA public key
	fmt.Printf("🔑 获取 RSA 公钥...\n")
	rsaResp, err := as.client.GetPasswordRSAPublicKey(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get RSA public key: %w", err)
	}

	// Step 2: Encrypt password
	fmt.Printf("🔐 加密密码...\n")
	encryptedPassword, err := EncryptPassword(password, rsaResp.PublicKeyMod, rsaResp.PublicKeyExp)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt password: %w", err)
	}

	// Step 3: Begin authentication session
	fmt.Printf("📡 开始认证会话...\n")
	beginReq := &BeginAuthSessionRequest{
		AccountName:         username,
		EncryptedPassword:   encryptedPassword,
		EncryptionTimestamp: rsaResp.Timestamp,
		RememberLogin:       true,
		PlatformType:        int32(EAuthTokenPlatformType_SteamClient),
		Persistence:         int32(ESessionPersistence_Persistent),
		WebsiteID:           "Client",
		DeviceDetails: &DeviceDetails{
			DeviceFriendlyName: "go-steam",
			PlatformType:       int32(EAuthTokenPlatformType_SteamClient),
			OSType:             -500, // Unknown
		},
	}

	// Add machine auth token if available
	if machineAuthToken != "" {
		fmt.Printf("🔑 使用 MachineAuthToken 进行认证...\n")
		beginReq.GuardData = machineAuthToken
	}

	beginResp, err := as.client.BeginAuthSessionViaCredentials(beginReq)
	if err != nil {
		return nil, fmt.Errorf("failed to begin auth session: %w", err)
	}

	as.clientID = beginResp.ClientID
	as.requestID = beginResp.RequestID
	as.steamID = beginResp.SteamID
	as.interval = beginResp.Interval

	if as.interval == 0 {
		as.interval = 1.0 // Default to 1 second
	}

	fmt.Printf("✅ 认证会话已创建\n")
	fmt.Printf("   ClientID: %s\n", as.clientID)
	fmt.Printf("   RequestID: %s\n", as.requestID)
	fmt.Printf("   SteamID: %s\n", as.steamID)
	fmt.Printf("   轮询间隔: %.1f 秒\n", as.interval)

	// Check if Steam Guard code is required
	if len(beginResp.AllowedConfirmations) > 0 {
		fmt.Printf("\n⚠️ 需要 Steam Guard 验证:\n")
		for _, conf := range beginResp.AllowedConfirmations {
			fmt.Printf("   - 类型 %d: %s\n", conf.ConfirmationType, conf.AssociatedMessage)
		}
	}

	// Step 4: Poll for authentication status
	return as.pollUntilComplete()
}

// SubmitSteamGuardCode allows submitting a Steam Guard code during authentication
func (as *AuthenticationSession) SubmitSteamGuardCode(code string, codeType int32) error {
	req := &UpdateAuthSessionRequest{
		ClientID: as.clientID,
		SteamID:  as.steamID,
		Code:     code,
		CodeType: codeType,
	}

	_, err := as.client.UpdateAuthSessionWithSteamGuardCode(req)
	if err != nil {
		return fmt.Errorf("failed to submit Steam Guard code: %w", err)
	}

	fmt.Printf("✅ Steam Guard 代码已提交\n")
	return nil
}

// LoginResult contains the authentication result
type LoginResult struct {
	RefreshToken     string
	AccessToken      string
	MachineAuthToken string
	AccountName      string
}

// pollUntilComplete polls the authentication status until completion
func (as *AuthenticationSession) pollUntilComplete() (*LoginResult, error) {
	fmt.Printf("\n🔄 开始轮询认证状态...\n")

	ticker := time.NewTicker(time.Duration(as.interval * float32(time.Second)))
	defer ticker.Stop()

	timeout := time.After(5 * time.Minute)
	pollCount := 0

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("authentication timed out after 5 minutes")

		case <-ticker.C:
			pollCount++
			fmt.Printf("   轮询 #%d...\n", pollCount)

			pollResp, err := as.client.PollAuthSessionStatus(as.clientID, as.requestID)
			if err != nil {
				// Some errors are expected during polling (e.g., "not yet complete")
				// Continue polling unless it's a critical error
				fmt.Printf("   ⚠️ 轮询出错: %v (继续等待...)\n", err)
				continue
			}

			// Check if we got tokens (authentication complete)
			if pollResp.RefreshToken != "" {
				fmt.Printf("\n🎉 认证成功！\n")

				result := &LoginResult{
					RefreshToken:     pollResp.RefreshToken,
					AccessToken:      pollResp.AccessToken,
					MachineAuthToken: pollResp.NewGuardData,
					AccountName:      pollResp.AccountName,
				}

				if result.MachineAuthToken != "" {
					fmt.Printf("   ✅ 获得 MachineAuthToken (长度: %d)\n", len(result.MachineAuthToken))
				}

				return result, nil
			}

			// Check for new challenge URL (might need additional verification)
			if pollResp.NewChallengeURL != "" {
				fmt.Printf("   ℹ️ 需要额外验证: %s\n", pollResp.NewChallengeURL)
			}
		}
	}
}

// LoginWithMachineAuthToken attempts to login using a saved machine auth token
// This is a convenience wrapper that calls LoginWithCredentials with the token
func (as *AuthenticationSession) LoginWithMachineAuthToken(username, password, machineAuthToken string) (*LoginResult, error) {
	return as.LoginWithCredentials(username, password, machineAuthToken)
}

// Helper function to convert string to uint64
func parseUint64(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

// GetClient returns the underlying AuthenticationClient
func (as *AuthenticationSession) GetClient() *AuthenticationClient {
	return as.client
}

// PollForResult polls for authentication result until completion
func (as *AuthenticationSession) PollForResult(clientID, requestID string, interval float32) (*LoginResult, error) {
	if interval == 0 {
		interval = 1.0
	}

	ticker := time.NewTicker(time.Duration(interval * float32(time.Second)))
	defer ticker.Stop()

	timeout := time.After(5 * time.Minute)
	pollCount := 0

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("authentication timed out after 5 minutes")

		case <-ticker.C:
			pollCount++
			if pollCount%5 == 0 {
				fmt.Printf("   轮询 #%d...\n", pollCount)
			}

			pollResp, err := as.client.PollAuthSessionStatus(clientID, requestID)
			if err != nil {
				// Some errors are expected during polling
				continue
			}

			// Check if we got tokens (authentication complete)
			if pollResp.RefreshToken != "" {
				result := &LoginResult{
					RefreshToken:     pollResp.RefreshToken,
					AccessToken:      pollResp.AccessToken,
					MachineAuthToken: pollResp.NewGuardData,
					AccountName:      pollResp.AccountName,
				}
				return result, nil
			}
		}
	}
}
