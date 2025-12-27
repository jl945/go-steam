package steam

import (
	"github.com/paralin/go-steam/protocol/steamlang"
	"github.com/paralin/go-steam/steamid"
)

type LoggedOnEvent struct {
	Result                    steamlang.EResult
	ExtendedResult            steamlang.EResult
	OutOfGameSecsPerHeartbeat int32
	InGameSecsPerHeartbeat    int32
	PublicIp                  uint32
	ServerTime                uint32
	AccountFlags              steamlang.EAccountFlags
	ClientSteamId             steamid.SteamId `json:",string"`
	EmailDomain               string
	CellId                    uint32
	CellIdPingThreshold       uint32
	Steam2Ticket              []byte
	UsePics                   bool
	WebApiUserNonce           string
	IpCountryCode             string
	VanityUrl                 string
	NumLoginFailuresToMigrate int32
	NumDisconnectsToMigrate   int32
}

type LogOnFailedEvent struct {
	Result steamlang.EResult
}

type LoginKeyEvent struct {
	UniqueId uint32
	LoginKey string
}

type LoggedOffEvent struct {
	Result steamlang.EResult
}

type MachineAuthUpdateEvent struct {
	Hash []byte
}

// MachineAuthTokenEvent is fired when a new machine auth token is received.
// This is the new JWT-based authentication token that replaces sentry hashes.
// You should save this token and use it for future logins.
type MachineAuthTokenEvent struct {
	Token string
}

// NewAuthenticationResultEvent is fired when authentication via new protocol completes.
// This event contains all authentication tokens returned by Steam's new auth system.
type NewAuthenticationResultEvent struct {
	RefreshToken     string // Long-lived token for refreshing access tokens
	AccessToken      string // Short-lived token for API calls
	MachineAuthToken string // JWT token for remember-this-device functionality
	AccountName      string // Steam account name
}

type AccountInfoEvent struct {
	PersonaName          string
	Country              string
	CountAuthedComputers int32
	AccountFlags         steamlang.EAccountFlags
	FacebookId           uint64 `json:",string"`
	FacebookName         string
}
