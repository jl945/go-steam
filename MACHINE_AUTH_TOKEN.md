# MachineAuthToken Support

本 fork 添加了对 Steam 新版 MachineAuthToken（JWT 格式）的支持，以替代即将弃用的 Sentry + LoginKey 认证机制。

## 新增功能

### 1. MachineAuthToken 字段

在 `LogOnDetails` 中新增了 `MachineAuthToken` 字段：

```go
type LogOnDetails struct {
    Username         string
    Password         string
    AuthCode         string
    TwoFactorCode    string
    SentryFileHash   SentryHash
    LoginKey         string
    MachineAuthToken string  // 新增：JWT 格式的机器认证 token
    ShouldRememberPassword bool
}
```

### 2. MachineAuthTokenEvent 事件

新增了 `MachineAuthTokenEvent` 事件，当收到新的 MachineAuthToken 时触发：

```go
type MachineAuthTokenEvent struct {
    Token string  // JWT 格式的 token
}
```

## 使用方法

### 基本使用

```go
package main

import (
    "fmt"
    "os"
    "strings"

    "github.com/Philipp15b/go-steam/v3"
)

func main() {
    steamClient := steam.NewClient()
    username := "your_username"

    logOnDetails := &steam.LogOnDetails{
        Username:               username,
        Password:               "your_password",
        ShouldRememberPassword: true,
    }

    // 尝试读取已保存的 MachineAuthToken
    if token, err := readMachineAuthToken(username); err == nil && token != "" {
        fmt.Println("使用已保存的 MachineAuthToken")
        logOnDetails.MachineAuthToken = token
    }

    steamClient.Connect()

    for event := range steamClient.Events() {
        switch e := event.(type) {
        case *steam.ConnectedEvent:
            steamClient.Auth.LogOn(logOnDetails)

        case *steam.MachineAuthTokenEvent:
            fmt.Println("收到新的 MachineAuthToken")
            // 保存 token 供下次使用
            saveMachineAuthToken(username, e.Token)

        case *steam.LoggedOnEvent:
            fmt.Println("登录成功")
        }
    }
}

func readMachineAuthToken(username string) (string, error) {
    filename := fmt.Sprintf("machineAuthToken_%s.txt", strings.ToLower(username))
    content, err := os.ReadFile(filename)
    if err != nil {
        if os.IsNotExist(err) {
            return "", nil
        }
        return "", err
    }
    return strings.TrimSpace(string(content)), nil
}

func saveMachineAuthToken(username, token string) error {
    filename := fmt.Sprintf("machineAuthToken_%s.txt", strings.ToLower(username))
    return os.WriteFile(filename, []byte(token), 0600)
}
```

### 完整示例

查看以下文件获取完整示例：
- `examples/machine_auth_token.go` - 基本认证示例
- `../main_with_machine_auth_token.go` - Dota2 Bot 完整示例

## 认证机制对比

| 特性 | MachineAuthToken (新) | LoginKey + Sentry (旧) |
|------|----------------------|----------------------|
| **格式** | JWT (文本) | LoginKey(文本) + Sentry(二进制) |
| **存储** | 单个文件（.txt） | 两个文件（.txt + .bin） |
| **状态** | 推荐使用 ✅ | 即将弃用 ⚠️ |
| **识别方法** | 以 "eyJ" 开头，包含两个 "." | 普通字符串 / 二进制哈希 |
| **安全性** | JWT 签名验证 | SHA-1 哈希 |

## 实现说明

### 当前限制

由于 go-steam 的 protobuf 定义尚未更新为最新的 Steam 协议，本实现使用了以下过渡方案：

1. **MachineAuthToken 通过 LoginKey 字段传输**：在 protobuf 更新前，MachineAuthToken 临时使用 `LoginKey` 字段发送
2. **自动识别 Token 类型**：通过检测 JWT 格式（以"eyJ"开头且包含两个"."）来区分 MachineAuthToken 和普通 LoginKey
3. **向后兼容**：仍然支持旧的 Sentry + LoginKey 机制

### Token 识别逻辑

```go
func isJWTToken(s string) bool {
    // JWT tokens have the format: header.payload.signature
    // The header is base64-encoded JSON starting with "eyJ"
    return len(s) > 10 && s[:3] == "eyJ" && strings.Count(s, ".") == 2
}
```

## 认证优先级

登录时的认证方式优先级：

1. **MachineAuthToken**（最高优先级，如果提供）
2. **LoginKey**（如果没有 MachineAuthToken）
3. **SentryFileHash + Password**（传统方式）
4. **Password only**（最基本方式）

## 迁移指南

### 从旧版迁移

如果你的代码当前使用 LoginKey 或 Sentry：

```go
// 旧代码
logOnDetails := &steam.LogOnDetails{
    Username: username,
    Password: password,
    SentryFileHash: sentryHash,  // 旧方式
    LoginKey: loginKey,           // 旧方式
}

// 新代码 - 添加 MachineAuthToken 支持
logOnDetails := &steam.LogOnDetails{
    Username:         username,
    Password:         password,
    MachineAuthToken: machineToken,  // 新方式（优先）
    // 保留旧方式作为回退
    SentryFileHash:   sentryHash,
    LoginKey:         loginKey,
}
```

### 处理多种认证事件

```go
for event := range steamClient.Events() {
    switch e := event.(type) {
    case *steam.MachineAuthTokenEvent:
        // 新版 token（推荐保存）
        fmt.Println("收到 MachineAuthToken")
        saveMachineAuthToken(username, e.Token)

    case *steam.LoginKeyEvent:
        // 旧版 LoginKey（可选保存）
        fmt.Println("收到 LoginKey（旧版）")

    case *steam.MachineAuthUpdateEvent:
        // 旧版 Sentry（可选保存）
        fmt.Println("收到 Sentry Hash（旧版）")
    }
}
```

## 文件存储建议

### 推荐的文件命名

```
machineAuthToken_<username>.txt  - 新版 token
loginkey.txt                     - 旧版 login key（可选保留）
sentry.bin                       - 旧版 sentry（可选保留）
```

### 文件权限

```go
// 使用 0600 权限保护敏感文件
os.WriteFile(filename, []byte(token), 0600)
```

## 故障排除

### Token 未被识别为 MachineAuthToken

检查 token 格式：
- JWT token 应该以 `eyJ` 开头
- 包含两个点号 `.` 分隔三部分
- 示例：`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature`

### 仍然需要输入 Steam Guard 代码

可能的原因：
1. Token 已过期或无效
2. Steam 服务器尚未完全支持新协议
3. 首次登录时仍需要验证

解决方法：
- 提供 `AuthCode` 或 `TwoFactorCode`
- 登录成功后会收到新的 MachineAuthToken

## 未来计划

- [ ] 更新 protobuf 定义，添加 `guard_data` 字段
- [ ] 实现完整的新版认证协议（`CAuthentication_BeginAuthSessionViaCredentials`）
- [ ] 支持 refresh token 机制
- [ ] 添加 token 过期检测和自动刷新

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

与原项目保持一致
