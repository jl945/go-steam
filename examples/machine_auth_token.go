package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/paralin/go-steam"
)

const (
	machineAuthTokenFile = "machineAuthToken_%s.txt" // %s 为账户名（小写）
)

// 读取保存的 MachineAuthToken
func readMachineAuthToken(username string) (string, error) {
	filename := fmt.Sprintf(machineAuthTokenFile, strings.ToLower(username))
	content, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // 文件不存在不是错误
		}
		return "", fmt.Errorf("读取 machineAuthToken 失败: %w", err)
	}
	return strings.TrimSpace(string(content)), nil
}

// 保存新的 MachineAuthToken
func saveMachineAuthToken(username, token string) error {
	if token == "" {
		return nil
	}
	filename := fmt.Sprintf(machineAuthTokenFile, strings.ToLower(username))
	err := os.WriteFile(filename, []byte(token), 0600)
	if err != nil {
		return fmt.Errorf("保存 machineAuthToken 失败: %w", err)
	}
	fmt.Printf("✅ 已保存 MachineAuthToken 到 %s\n", filename)
	return nil
}

func main() {
	username := "your_username"
	password := "your_password"

	// 创建 Steam 客户端
	steamClient := steam.NewClient()

	// 准备登录信息
	logOnDetails := &steam.LogOnDetails{
		Username:               username,
		Password:               password,
		ShouldRememberPassword: true,
	}

	// 尝试读取已保存的 MachineAuthToken
	machineToken, err := readMachineAuthToken(username)
	if err != nil {
		fmt.Printf("⚠️ 读取 MachineAuthToken 失败: %v\n", err)
	} else if machineToken != "" {
		fmt.Println("🔑 使用已保存的 MachineAuthToken 登录")
		logOnDetails.MachineAuthToken = machineToken
		// 使用 token 登录时，可以不提供密码（如果 Steam 服务器支持）
		// logOnDetails.Password = ""
	} else {
		fmt.Println("📝 未找到 MachineAuthToken，首次登录")
	}

	// 连接到 Steam
	steamClient.Connect()

	// 事件循环
	for event := range steamClient.Events() {
		switch e := event.(type) {
		case *steam.ConnectedEvent:
			fmt.Println("✅ 已连接到 Steam 服务器")
			steamClient.Auth.LogOn(logOnDetails)

		case *steam.LoggedOnEvent:
			fmt.Println("✅ 成功登录 Steam")
			fmt.Printf("   SteamID: %v\n", e.ClientSteamId)

		case *steam.LogOnFailedEvent:
			fmt.Printf("❌ 登录失败: %v\n", e.Result)
			return

		case *steam.MachineAuthTokenEvent:
			// 收到新的 MachineAuthToken（JWT 格式）
			fmt.Println("📥 收到新的 MachineAuthToken")
			fmt.Printf("   Token (前30字符): %s...\n", e.Token[:min(30, len(e.Token))])

			if err := saveMachineAuthToken(username, e.Token); err != nil {
				fmt.Printf("❌ 保存失败: %v\n", err)
			}

		case *steam.LoginKeyEvent:
			// 收到 LoginKey（旧版机制）
			fmt.Println("📥 收到 LoginKey（旧版）")
			// 你可以选择保存 LoginKey，但推荐使用 MachineAuthToken

		case *steam.MachineAuthUpdateEvent:
			// 收到 Sentry Hash（旧版机制）
			fmt.Println("📥 收到 Sentry Hash（旧版）")
			// 这是旧版的机器认证，新代码推荐使用 MachineAuthToken

		case *steam.LoggedOffEvent:
			fmt.Printf("🔌 已断开连接: %v\n", e.Result)
			return

		case *steam.DisconnectedEvent:
			fmt.Println("🔌 与 Steam 服务器断开连接")
			return
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
