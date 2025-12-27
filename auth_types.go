package steam

// Authentication enums and messages for new Steam authentication protocol

// EAuthTokenPlatformType represents the platform type for authentication
type EAuthTokenPlatformType int32

const (
	EAuthTokenPlatformType_Unknown     EAuthTokenPlatformType = 0
	EAuthTokenPlatformType_SteamClient EAuthTokenPlatformType = 1
	EAuthTokenPlatformType_WebBrowser  EAuthTokenPlatformType = 2
	EAuthTokenPlatformType_MobileApp   EAuthTokenPlatformType = 3
)

// EAuthSessionGuardType represents the guard type for authentication
type EAuthSessionGuardType int32

const (
	EAuthSessionGuardType_Unknown             EAuthSessionGuardType = 0
	EAuthSessionGuardType_None                EAuthSessionGuardType = 1
	EAuthSessionGuardType_EmailCode           EAuthSessionGuardType = 2
	EAuthSessionGuardType_DeviceCode          EAuthSessionGuardType = 3
	EAuthSessionGuardType_DeviceConfirmation  EAuthSessionGuardType = 4
	EAuthSessionGuardType_EmailConfirmation   EAuthSessionGuardType = 5
	EAuthSessionGuardType_MachineToken        EAuthSessionGuardType = 6
	EAuthSessionGuardType_LegacyMachineAuth   EAuthSessionGuardType = 7
)

// ESessionPersistence represents whether the session should be persistent
type ESessionPersistence int32

const (
	ESessionPersistence_Invalid    ESessionPersistence = 0
	ESessionPersistence_Ephemeral  ESessionPersistence = 1
	ESessionPersistence_Persistent ESessionPersistence = 2
)

// Authentication request/response messages

type AuthenticationDeviceDetails struct {
	DeviceFriendlyName *string
	PlatformType       *EAuthTokenPlatformType
	OsType             *int32
	GamingDeviceType   *uint32
	ClientCount        *uint32
	MachineId          []byte
}

type AuthenticationAllowedConfirmation struct {
	ConfirmationType  *EAuthSessionGuardType
	AssociatedMessage *string
}

// GetPasswordRSAPublicKey messages
type AuthenticationGetPasswordRSAPublicKeyRequest struct {
	AccountName *string
}

type AuthenticationGetPasswordRSAPublicKeyResponse struct {
	PublicKeyMod *string
	PublicKeyExp *string
	Timestamp    *uint64
}

// BeginAuthSessionViaCredentials messages
type AuthenticationBeginAuthSessionViaCredentialsRequest struct {
	DeviceFriendlyName *string
	AccountName        *string
	EncryptedPassword  *string
	EncryptionTimestamp *uint64
	RememberLogin      *bool
	PlatformType       *EAuthTokenPlatformType
	Persistence        *ESessionPersistence
	WebsiteId          *string
	DeviceDetails      *AuthenticationDeviceDetails
	GuardData          *string
	Language           *uint32
	QosLevel           *int32
}

type AuthenticationBeginAuthSessionViaCredentialsResponse struct {
	ClientId             *uint64
	RequestId            []byte
	Interval             *float32
	AllowedConfirmations []*AuthenticationAllowedConfirmation
	SteamId              *uint64
	WeakToken            *string
	AgreementSessionUrl  *string
	ExtendedErrorMessage *string
}

// PollAuthSessionStatus messages
type AuthenticationPollAuthSessionStatusRequest struct {
	ClientId      *uint64
	RequestId     []byte
	TokenToRevoke *uint64
}

type AuthenticationPollAuthSessionStatusResponse struct {
	NewClientId           *uint64
	NewChallengeUrl       *string
	RefreshToken          *string
	AccessToken           *string
	HadRemoteInteraction  *bool
	AccountName           *string
	NewGuardData          *string  // This is the MachineAuthToken!
	AgreementSessionUrl   *string
}

// UpdateAuthSessionWithSteamGuardCode messages
type AuthenticationUpdateAuthSessionWithSteamGuardCodeRequest struct {
	ClientId *uint64
	SteamId  *uint64
	Code     *string
	CodeType *EAuthSessionGuardType
}

type AuthenticationUpdateAuthSessionWithSteamGuardCodeResponse struct {
	AgreementSessionUrl *string
}
