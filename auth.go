package steam

import (
	"crypto/sha1"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/paralin/go-steam/protocol"
	"github.com/paralin/go-steam/protocol/protobuf"
	"github.com/paralin/go-steam/protocol/steamlang"
	"github.com/paralin/go-steam/steamid"
	"google.golang.org/protobuf/proto"
)

type Auth struct {
	client  *Client
	details *LogOnDetails
}

type SentryHash []byte

// getOsType returns the appropriate EOSType for the current operating system
// 参考 node-steam-user helpers.js getOsType()
func getOsType() uint32 {
	var osType steamlang.EOSType
	switch runtime.GOOS {
	case "darwin":
		osType = steamlang.EOSType_MacOSUnknown // -102
	case "linux":
		osType = steamlang.EOSType_LinuxUnknown // -203
	case "windows":
		osType = steamlang.EOSType_Windows10 // 16
	default:
		osType = steamlang.EOSType_WinUnknown // 0
	}
	fmt.Println("getOsType----", int32(osType))

	// Convert signed int32 to uint32 (Steam accepts both signed and unsigned)
	return uint32(osType)
}

type LogOnDetails struct {
	Username string

	// If logging into an account without a login key, the account's password.
	Password string

	// If you have a Steam Guard email code, you can provide it here.
	AuthCode string

	// If you have a Steam Guard mobile two-factor authentication code, you can provide it here.
	TwoFactorCode  string
	SentryFileHash SentryHash
	LoginKey       string

	// MachineAuthToken is the new JWT-based machine authentication token.
	// This replaces the old SentryFileHash mechanism.
	// If provided, it will be sent as guard data to Steam.
	MachineAuthToken string

	// AccessToken is the refresh token obtained from the new authentication flow.
	// When provided, it will be used for token-based login (no password required).
	// This is the recommended way to login after the first authentication.
	AccessToken string

	// true if you want to get a login key which can be used in lieu of
	// a password for subsequent logins. false or omitted otherwise.
	ShouldRememberPassword bool
}

// Log on with the given details. You must always specify username and
// password OR username and loginkey. For the first login, don't set an authcode or a hash and you'll
//
//	receive an error (EResult_AccountLogonDenied)
//
// and Steam will send you an authcode. Then you have to login again, this time with the authcode.
// Shortly after logging in, you'll receive a MachineAuthUpdateEvent with a hash which allows
// you to login without using an authcode in the future.
//
// Alternatively, you can use MachineAuthToken (new JWT-based auth) which will be stored
// and sent via LoginKey mechanism until full protocol support is added.
//
// If you don't use Steam Guard, username and password are enough.
//
// After the event EMsg_ClientNewLoginKey is received you can use the LoginKey
// to login instead of using the password.
func (a *Auth) LogOn(details *LogOnDetails) {
	// Validate AccessToken usage (参考 node-steam-user 09-logon.js:122-135)
	if details.AccessToken != "" {
		// When using AccessToken (refresh token), these fields cannot be set
		if details.Username != "" {
			panic("Cannot specify Username when logging in with AccessToken (refresh token)")
		}
		if details.Password != "" {
			panic("Cannot specify Password when logging in with AccessToken (refresh token)")
		}
		if details.AuthCode != "" {
			panic("Cannot specify AuthCode when logging in with AccessToken (refresh token)")
		}
		if details.TwoFactorCode != "" {
			panic("Cannot specify TwoFactorCode when logging in with AccessToken (refresh token)")
		}
		if details.MachineAuthToken != "" {
			panic("Cannot specify MachineAuthToken when logging in with AccessToken (refresh token)")
		}
	} else {
		// When not using AccessToken, Username is required
		if details.Username == "" {
			panic("Username must be set!")
		}
		if details.Password == "" && details.LoginKey == "" && details.MachineAuthToken == "" {
			panic("Password, LoginKey, or MachineAuthToken must be set!")
		}
	}

	logon := new(protobuf.CMsgClientLogon)
	fmt.Println("---details.AccessToken--", details.AccessToken)
	// Prefer AccessToken (refresh token) for new authentication flow
	if details.AccessToken != "" {
		// 参考 node-steam-user 09-logon.js:84, 124-135
		// 使用 refreshToken 时，不设置 account_name 和 password
		// ❌ DO NOT set Password field at all (not even to empty string)
		// In protobuf, nil means field is not sent, proto.String("") means sending empty value
		logon.AccessToken = proto.String(details.AccessToken)

		// Parse SteamID from AccessToken JWT (参考 node-steam-user 09-logon.js:140-163)
		steamID, err := ParseSteamIDFromJWT(details.AccessToken)
		if err != nil {
			panic(fmt.Sprintf("Failed to parse SteamID from AccessToken: %v", err))
		}

		// Set the SteamID from the token (参考 node-steam-user 09-logon.js:163)
		// This ensures the correct SteamID is used in the message header
		atomic.StoreUint64(&a.client.steamId, steamID)

		// 参考 node-steam-user 09-logon.js:91-98，使用 refreshToken 时必须设置这些字段
		logon.SupportsRateLimitResponse = proto.Bool(true)
		logon.MachineName = proto.String("")
		logon.ChatMode = proto.Uint32(2) // enable new chat
		logon.ObfuscatedPrivateIp = &protobuf.CMsgIPAddress{
			Ip: &protobuf.CMsgIPAddress_V4{V4: 0},
		}
		// 生成 machine_id (参考 node-steam-user 09-logon.js:223-224)
		logon.MachineId = generateMachineIDFromSteamID(steamID)
		// client_os_type will be set below
	} else {
		// Password/key-based login
		logon.AccountName = &details.Username
		logon.Password = &details.Password

		// For password/key-based login, set a temporary SteamID (参考 node-steam-user 09-logon.js:231-236)
		atomic.StoreUint64(&a.client.steamId, uint64(steamid.NewIdAdv(0, 1, int32(steamlang.EUniverse_Public), int32(steamlang.EAccountType_Individual))))
	}

	if details.AuthCode != "" {
		logon.AuthCode = proto.String(details.AuthCode)
	}
	if details.TwoFactorCode != "" {
		logon.TwoFactorCode = proto.String(details.TwoFactorCode)
	}
	logon.ClientLanguage = proto.String("english")
	logon.ProtocolVersion = proto.Uint32(steamlang.MsgClientLogon_CurrentProtocol)
	logon.ClientOsType = proto.Uint32(getOsType()) // 参考 node-steam-user 09-logon.js:95

	fmt.Println("Before final print - AccessToken:", *logon.AccessToken)

	// Prefer MachineAuthToken over SentryFileHash (new vs old mechanism)
	// Note: Until protobuf is updated to support guard_data field,
	// we use the LoginKey field to transmit MachineAuthToken as a fallback
	// Only use this if AccessToken is not provided
	if details.AccessToken == "" {
		if details.MachineAuthToken != "" {
			logon.LoginKey = proto.String(details.MachineAuthToken)
		} else if details.LoginKey != "" {
			logon.LoginKey = proto.String(details.LoginKey)
		}
	}

	// Still support old sentry mechanism
	if details.SentryFileHash != nil && details.MachineAuthToken == "" && details.AccessToken == "" {
		logon.ShaSentryfile = details.SentryFileHash
	}

	if details.ShouldRememberPassword {
		logon.ShouldRememberPassword = proto.Bool(details.ShouldRememberPassword)
	}

	// Debug: Check AccessToken right before serialization
	if logon.AccessToken != nil {
		fmt.Println("AccessToken before String():", *logon.AccessToken)
	}
	fmt.Println("-----", logon.String())

	// Debug: Check if AccessToken field is set
	fmt.Printf("Has AccessToken field: %v\n", logon.AccessToken != nil)

	// Debug: Try to serialize and check what's actually being sent
	data, err := proto.Marshal(logon)
	if err != nil {
		fmt.Println("Marshal error:", err)
	} else {
		//fmt.Printf("Serialized data length: %d bytes\n", len(data))
		// Try to deserialize to verify
		testMsg := &protobuf.CMsgClientLogon{}
		if err := proto.Unmarshal(data, testMsg); err == nil {
			if testMsg.AccessToken != nil {
				//fmt.Println("Deserialized AccessToken exists:", *testMsg.AccessToken)
			} else {
				fmt.Println("Deserialized AccessToken is NIL!")
			}
		}
	}

	a.client.Write(protocol.NewClientMsgProtobuf(steamlang.EMsg_ClientLogon, logon))
}

func (a *Auth) HandlePacket(packet *protocol.Packet) {
	switch packet.EMsg {
	case steamlang.EMsg_ClientLogOnResponse:
		a.handleLogOnResponse(packet)
	case steamlang.EMsg_ClientNewLoginKey:
		a.handleLoginKey(packet)
	case steamlang.EMsg_ClientSessionToken:
	case steamlang.EMsg_ClientLoggedOff:
		a.handleLoggedOff(packet)
	case steamlang.EMsg_ClientUpdateMachineAuth:
		a.handleUpdateMachineAuth(packet)
	case steamlang.EMsg_ClientAccountInfo:
		a.handleAccountInfo(packet)
	}
}

func (a *Auth) handleLogOnResponse(packet *protocol.Packet) {
	if !packet.IsProto {
		a.client.Fatalf("Got non-proto logon response!")
		return
	}

	body := new(protobuf.CMsgClientLogonResponse)
	msg := packet.ReadProtoMsg(body)

	result := steamlang.EResult(body.GetEresult())
	if result == steamlang.EResult_OK {
		atomic.StoreInt32(&a.client.sessionId, msg.Header.Proto.GetClientSessionid())
		atomic.StoreUint64(&a.client.steamId, msg.Header.Proto.GetSteamid())

		// Note: WebapiAuthenticateUserNonce was moved to a separate message in newer protobuf
		// For now, we'll skip this field as it's not in CMsgClientLogonResponse anymore

		// Use HeartbeatSeconds (new field) instead of deprecated LegacyOutOfGameHeartbeatSeconds
		heartbeatSecs := body.GetHeartbeatSeconds()
		if heartbeatSecs == 0 {
			// Fallback to legacy field if new field is not set
			heartbeatSecs = body.GetLegacyOutOfGameHeartbeatSeconds()
		}
		go a.client.heartbeatLoop(time.Duration(heartbeatSecs))

		a.client.Emit(&LoggedOnEvent{
			Result:                    steamlang.EResult(body.GetEresult()),
			ExtendedResult:            steamlang.EResult(body.GetEresultExtended()),
			OutOfGameSecsPerHeartbeat: heartbeatSecs,
			InGameSecsPerHeartbeat:    heartbeatSecs, // Use same value as in/out game is unified now
			PublicIp:                  body.GetDeprecatedPublicIp(),
			ServerTime:                body.GetRtime32ServerTime(),
			AccountFlags:              steamlang.EAccountFlags(body.GetAccountFlags()),
			ClientSteamId:             steamid.SteamId(body.GetClientSuppliedSteamid()),
			EmailDomain:               body.GetEmailDomain(),
			CellId:                    body.GetCellId(),
			CellIdPingThreshold:       body.GetCellIdPingThreshold(),
			Steam2Ticket:              body.GetSteam2Ticket(),
			UsePics:                   body.GetDeprecatedUsePics(),
			WebApiUserNonce:           "", // Field no longer in CMsgClientLogonResponse
			IpCountryCode:             body.GetIpCountryCode(),
			VanityUrl:                 body.GetVanityUrl(),
			NumLoginFailuresToMigrate: body.GetCountLoginfailuresToMigrate(),
			NumDisconnectsToMigrate:   body.GetCountDisconnectsToMigrate(),
		})
	} else if result == steamlang.EResult_Fail || result == steamlang.EResult_ServiceUnavailable || result == steamlang.EResult_TryAnotherCM {
		// some error on Steam's side, we'll get an EOF later
	} else {
		a.client.Emit(&LogOnFailedEvent{
			Result: steamlang.EResult(body.GetEresult()),
		})
		a.client.Disconnect()
	}
}

func (a *Auth) handleLoginKey(packet *protocol.Packet) {
	body := new(protobuf.CMsgClientNewLoginKey)
	packet.ReadProtoMsg(body)
	a.client.Write(protocol.NewClientMsgProtobuf(steamlang.EMsg_ClientNewLoginKeyAccepted, &protobuf.CMsgClientNewLoginKeyAccepted{
		UniqueId: proto.Uint32(body.GetUniqueId()),
	}))

	loginKey := body.GetLoginKey()

	// Debug: Log what we received
	a.client.Emit(&struct {
		Message string
		Key     string
	}{
		Message: "DEBUG: Received LoginKey",
		Key:     loginKey,
	})

	// Check if this is a JWT token (MachineAuthToken) or a regular LoginKey
	// JWT tokens typically start with "eyJ" (base64-encoded JSON header)
	if isJWTToken(loginKey) {
		// This is a new MachineAuthToken
		a.client.Emit(&MachineAuthTokenEvent{
			Token: loginKey,
		})
	} else {
		// This is a regular LoginKey
		a.client.Emit(&LoginKeyEvent{
			UniqueId: body.GetUniqueId(),
			LoginKey: loginKey,
		})
	}
}

// isJWTToken checks if a string looks like a JWT token
func isJWTToken(s string) bool {
	// JWT tokens have the format: header.payload.signature
	// The header is base64-encoded JSON starting with "eyJ"
	return len(s) > 10 && s[:3] == "eyJ" && strings.Count(s, ".") == 2
}

func (a *Auth) handleLoggedOff(packet *protocol.Packet) {
	result := steamlang.EResult_Invalid
	if packet.IsProto {
		body := new(protobuf.CMsgClientLoggedOff)
		packet.ReadProtoMsg(body)
		result = steamlang.EResult(body.GetEresult())
	} else {
		body := new(steamlang.MsgClientLoggedOff)
		packet.ReadClientMsg(body)
		result = body.Result
	}
	a.client.Emit(&LoggedOffEvent{Result: result})
}

func (a *Auth) handleUpdateMachineAuth(packet *protocol.Packet) {
	body := new(protobuf.CMsgClientUpdateMachineAuth)
	packet.ReadProtoMsg(body)
	hash := sha1.New()
	hash.Write(packet.Data)
	sha := hash.Sum(nil)

	msg := protocol.NewClientMsgProtobuf(steamlang.EMsg_ClientUpdateMachineAuthResponse, &protobuf.CMsgClientUpdateMachineAuthResponse{
		ShaFile: sha,
	})
	msg.SetTargetJobId(packet.SourceJobId)
	a.client.Write(msg)

	a.client.Emit(&MachineAuthUpdateEvent{sha})
}

func (a *Auth) handleAccountInfo(packet *protocol.Packet) {
	body := new(protobuf.CMsgClientAccountInfo)
	packet.ReadProtoMsg(body)
	a.client.Emit(&AccountInfoEvent{
		PersonaName:          body.GetPersonaName(),
		Country:              body.GetIpCountry(),
		CountAuthedComputers: body.GetCountAuthedComputers(),
		AccountFlags:         steamlang.EAccountFlags(body.GetAccountFlags()),
		FacebookId:           0,  // Field removed in newer protobuf
		FacebookName:         "", // Field removed in newer protobuf
	})
}

// LogOnWithNewProtocol uses the new HTTP-based authentication protocol to obtain a MachineAuthToken.
// This is the recommended method for new implementations as the old LoginKey mechanism is deprecated.
//
// Usage:
//  1. Call this method with username and password (and optional existing MachineAuthToken)
//  2. Listen for MachineAuthTokenEvent to get the new token
//  3. Save the token for future logins
//  4. The method will automatically emit LoggedOnEvent upon successful authentication
//
// Note: This method uses HTTPS API calls instead of the TCP Steam protocol.
// If you need Steam Guard codes, you should call SubmitSteamGuardCode on the session.
func (a *Auth) LogOnWithNewProtocol(details *LogOnDetails) error {
	if details.Username == "" {
		return fmt.Errorf("username must be set")
	}
	if details.Password == "" {
		return fmt.Errorf("password must be set")
	}

	// Store details for potential later use
	a.details = details

	// Create authentication session
	session := NewAuthenticationSession()

	// Perform login with credentials
	result, err := session.LoginWithCredentials(
		details.Username,
		details.Password,
		details.MachineAuthToken,
	)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Emit MachineAuthToken event if we got one
	if result.MachineAuthToken != "" {
		a.client.Emit(&MachineAuthTokenEvent{
			Token: result.MachineAuthToken,
		})
	}

	// Store the new tokens (could be used for future API calls)
	// For now, we emit a custom event with all the auth data
	a.client.Emit(&NewAuthenticationResultEvent{
		RefreshToken:     result.RefreshToken,
		AccessToken:      result.AccessToken,
		MachineAuthToken: result.MachineAuthToken,
		AccountName:      result.AccountName,
	})

	return nil
}
