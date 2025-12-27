package steam

import (
	"fmt"
	"time"
)

// SimpleAuthSession manages a simplified authentication session
type SimpleAuthSession struct {
	client    *SimpleAuthClient
	clientID  uint64
	requestID []byte
	steamID   uint64
	interval  float32
}

// NewSimpleAuthSession creates a new simplified authentication session
func NewSimpleAuthSession() *SimpleAuthSession {
	return &SimpleAuthSession{
		client: NewSimpleAuthClient(),
	}
}

// SetSessionInfo sets the session information for manual polling
func (s *SimpleAuthSession) SetSessionInfo(clientID uint64, requestID []byte, interval float32, steamID uint64) {
	s.clientID = clientID
	s.requestID = requestID
	s.interval = interval
	s.steamID = steamID
	if s.interval == 0 {
		s.interval = 1.0
	}
}

// LoginWithCredentials performs complete authentication flow
func (s *SimpleAuthSession) LoginWithCredentials(username, password, machineAuthToken string) (*SimpleLoginResult, error) {
	// Step 1: Get RSA public key
	fmt.Printf("🔑 获取 RSA 公钥...\n")
	mod, exp, timestamp, err := s.client.GetPasswordRSAPublicKey(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get RSA key: %w", err)
	}

	fmt.Printf("✅ 成功 (timestamp: %d)\n", timestamp)

	// Step 2: Encrypt password
	fmt.Printf("🔐 加密密码...\n")
	encryptedPassword, err := EncryptPassword(password, mod, exp)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt password: %w", err)
	}

	fmt.Printf("✅ 成功\n")

	// Step 3: Begin authentication session
	fmt.Printf("📡 开始认证会话...\n")
	clientID, requestID, interval, steamID, err := s.client.BeginAuthSession(
		username,
		encryptedPassword,
		timestamp,
		machineAuthToken,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to begin auth session: %w", err)
	}

	s.clientID = clientID
	s.requestID = requestID
	s.interval = interval
	s.steamID = steamID

	if s.interval == 0 {
		s.interval = 1.0
	}

	fmt.Printf("✅ 成功！\n")
	fmt.Printf("   ClientID: %d\n", clientID)
	fmt.Printf("   SteamID: %d\n", steamID)
	fmt.Printf("   轮询间隔: %.1f 秒\n", s.interval)

	// Step 4: Poll for completion
	return s.PollUntilComplete()
}

// PollUntilComplete polls until authentication completes
func (s *SimpleAuthSession) PollUntilComplete() (*SimpleLoginResult, error) {
	fmt.Printf("\n🔄 开始轮询认证状态...\n")
	fmt.Printf("💡 如果有 MachineAuthToken，通常会立即通过\n")
	fmt.Printf("💡 否则请查看邮箱并点击确认链接，或输入验证码\n\n")

	ticker := time.NewTicker(time.Duration(s.interval * float32(time.Second)))
	defer ticker.Stop()

	timeout := time.After(2 * time.Minute) // 缩短超时时间到 2 分钟
	pollCount := 0
	startTime := time.Now()

	for {
		select {
		case <-timeout:
			elapsed := time.Since(startTime)
			return nil, fmt.Errorf("认证超时 (已等待 %.0f 秒)。可能原因：\n"+
				"  1. MachineAuthToken 已失效，请删除文件重新验证\n"+
				"  2. 需要在邮箱中点击确认链接\n"+
				"  3. 网络连接问题", elapsed.Seconds())

		case <-ticker.C:
			pollCount++
			elapsed := time.Since(startTime)
			fmt.Printf("   [%.0fs] 轮询 #%d...", elapsed.Seconds(), pollCount)

			refreshToken, accessToken, newGuardData, accountName, err := s.client.PollAuthSessionStatus(
				s.clientID,
				s.requestID,
			)

			if err != nil {
				// Some errors are expected (session not ready)
				fmt.Printf(" 等待中 (%v)\n", err)

				// 每 30 秒提示一次
				if pollCount > 0 && pollCount%30 == 0 {
					fmt.Printf("\n⚠️  已等待 %.0f 秒，仍在等待验证...\n", elapsed.Seconds())
					fmt.Printf("   请检查邮箱或考虑重新开始认证流程\n\n")
				}
				continue
			}

			// Check if authentication is complete
			if refreshToken != "" {
				fmt.Printf(" ✅ 成功！\n")
				fmt.Printf("\n🎉 认证成功！(耗时 %.0f 秒)\n", elapsed.Seconds())

				result := &SimpleLoginResult{
					RefreshToken:     refreshToken,
					AccessToken:      accessToken,
					MachineAuthToken: newGuardData,
					AccountName:      accountName,
					SteamID:          s.steamID,
				}

				if newGuardData != "" {
					fmt.Printf("   ✅ 获得新的 MachineAuthToken (长度: %d)\n", len(newGuardData))
				}

				return result, nil
			}

			fmt.Printf(" 等待中...\n")
		}
	}
}

// SimpleLoginResult contains authentication result
type SimpleLoginResult struct {
	RefreshToken     string
	AccessToken      string
	MachineAuthToken string
	AccountName      string
	SteamID          uint64
}
