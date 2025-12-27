package steam

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SimpleProtoEncoder provides basic protobuf wire encoding
type SimpleProtoEncoder struct {
	buf []byte
}

func NewSimpleProtoEncoder() *SimpleProtoEncoder {
	return &SimpleProtoEncoder{buf: make([]byte, 0, 1024)}
}

func (e *SimpleProtoEncoder) Bytes() []byte {
	return e.buf
}

func (e *SimpleProtoEncoder) writeVarint(val uint64) {
	for val >= 0x80 {
		e.buf = append(e.buf, byte(val)|0x80)
		val >>= 7
	}
	e.buf = append(e.buf, byte(val))
}

func (e *SimpleProtoEncoder) writeTag(fieldNum int, wireType int) {
	e.writeVarint(uint64(fieldNum<<3 | wireType))
}

func (e *SimpleProtoEncoder) WriteString(fieldNum int, val string) {
	if val == "" {
		return
	}
	e.writeTag(fieldNum, 2) // Wire type 2 = length-delimited
	e.writeVarint(uint64(len(val)))
	e.buf = append(e.buf, []byte(val)...)
}

func (e *SimpleProtoEncoder) WriteUint64(fieldNum int, val uint64) {
	if val == 0 {
		return
	}
	e.writeTag(fieldNum, 0) // Wire type 0 = varint
	e.writeVarint(val)
}

func (e *SimpleProtoEncoder) WriteInt32(fieldNum int, val int32) {
	if val == 0 {
		return
	}
	e.writeTag(fieldNum, 0)
	// For negative numbers, encode as uint64
	e.writeVarint(uint64(val))
}

func (e *SimpleProtoEncoder) WriteUint32(fieldNum int, val uint32) {
	if val == 0 {
		return
	}
	e.writeTag(fieldNum, 0)
	e.writeVarint(uint64(val))
}

func (e *SimpleProtoEncoder) WriteBool(fieldNum int, val bool) {
	if !val {
		return
	}
	e.writeTag(fieldNum, 0)
	e.buf = append(e.buf, 1)
}

func (e *SimpleProtoEncoder) WriteBytes(fieldNum int, val []byte) {
	if len(val) == 0 {
		return
	}
	e.writeTag(fieldNum, 2)
	e.writeVarint(uint64(len(val)))
	e.buf = append(e.buf, val...)
}

func (e *SimpleProtoEncoder) WriteFloat32(fieldNum int, val float32) {
	if val == 0 {
		return
	}
	e.writeTag(fieldNum, 5) // Wire type 5 = 32-bit
	bits := math.Float32bits(val)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], bits)
	e.buf = append(e.buf, b[:]...)
}

func (e *SimpleProtoEncoder) WriteFixed64(fieldNum int, val uint64) {
	if val == 0 {
		return
	}
	e.writeTag(fieldNum, 1) // Wire type 1 = 64-bit fixed
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], val)
	e.buf = append(e.buf, b[:]...)
}

func (e *SimpleProtoEncoder) WriteMessage(fieldNum int, msg []byte) {
	if len(msg) == 0 {
		return
	}
	e.writeTag(fieldNum, 2)
	e.writeVarint(uint64(len(msg)))
	e.buf = append(e.buf, msg...)
}

// SimpleProtoDecoder provides basic protobuf wire decoding
type SimpleProtoDecoder struct {
	buf []byte
	pos int
}

func NewSimpleProtoDecoder(data []byte) *SimpleProtoDecoder {
	return &SimpleProtoDecoder{buf: data, pos: 0}
}

func (d *SimpleProtoDecoder) readVarint() (uint64, error) {
	var val uint64
	var shift uint
	for {
		if d.pos >= len(d.buf) {
			return 0, fmt.Errorf("unexpected EOF")
		}
		b := d.buf[d.pos]
		d.pos++
		val |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return val, nil
}

func (d *SimpleProtoDecoder) ReadField() (fieldNum int, wireType int, err error) {
	if d.pos >= len(d.buf) {
		return 0, 0, io.EOF
	}
	tag, err := d.readVarint()
	if err != nil {
		return 0, 0, err
	}
	return int(tag >> 3), int(tag & 7), nil
}

func (d *SimpleProtoDecoder) ReadString() (string, error) {
	length, err := d.readVarint()
	if err != nil {
		return "", err
	}
	if d.pos+int(length) > len(d.buf) {
		return "", fmt.Errorf("unexpected EOF")
	}
	str := string(d.buf[d.pos : d.pos+int(length)])
	d.pos += int(length)
	return str, nil
}

func (d *SimpleProtoDecoder) ReadBytes() ([]byte, error) {
	length, err := d.readVarint()
	if err != nil {
		return nil, err
	}
	if d.pos+int(length) > len(d.buf) {
		return nil, fmt.Errorf("unexpected EOF")
	}
	data := make([]byte, length)
	copy(data, d.buf[d.pos:d.pos+int(length)])
	d.pos += int(length)
	return data, nil
}

func (d *SimpleProtoDecoder) ReadUint64() (uint64, error) {
	return d.readVarint()
}

func (d *SimpleProtoDecoder) ReadFloat32() (float32, error) {
	if d.pos+4 > len(d.buf) {
		return 0, fmt.Errorf("unexpected EOF")
	}
	bits := binary.LittleEndian.Uint32(d.buf[d.pos : d.pos+4])
	d.pos += 4
	return math.Float32frombits(bits), nil
}

func (d *SimpleProtoDecoder) Skip(wireType int) error {
	switch wireType {
	case 0: // Varint
		_, err := d.readVarint()
		return err
	case 1: // 64-bit
		d.pos += 8
		return nil
	case 2: // Length-delimited
		length, err := d.readVarint()
		if err != nil {
			return err
		}
		d.pos += int(length)
		return nil
	case 5: // 32-bit
		d.pos += 4
		return nil
	default:
		return fmt.Errorf("unknown wire type: %d", wireType)
	}
}

// SimpleAuthClient uses simple protobuf encoding for authentication
type SimpleAuthClient struct {
	httpClient *http.Client
}

func NewSimpleAuthClient() *SimpleAuthClient {
	return &SimpleAuthClient{
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *SimpleAuthClient) callAPI(service, method string, reqData []byte, useGET bool) ([]byte, error) {
	apiURL := fmt.Sprintf("https://api.steampowered.com/%s/%s/v1/", service, method)
	encodedData := base64.StdEncoding.EncodeToString(reqData)

	var req *http.Request
	var err error

	if useGET {
		params := url.Values{}
		params.Set("input_protobuf_encoded", encodedData)
		req, err = http.NewRequest("GET", apiURL+"?"+params.Encode(), nil)
	} else {
		formData := url.Values{}
		formData.Set("input_protobuf_encoded", encodedData)
		req, err = http.NewRequest("POST", apiURL, strings.NewReader(formData.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "go-steam")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Check EResult header
	eresult := resp.Header.Get("X-eresult")
	if eresult != "" && eresult != "1" {
		errorMsg := resp.Header.Get("X-error_message")
		return nil, fmt.Errorf("Steam error (EResult %s): %s", eresult, errorMsg)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetPasswordRSAPublicKey fetches RSA public key
func (c *SimpleAuthClient) GetPasswordRSAPublicKey(accountName string) (mod, exp string, timestamp uint64, err error) {
	// Encode request
	enc := NewSimpleProtoEncoder()
	enc.WriteString(1, accountName)

	respData, err := c.callAPI("IAuthenticationService", "GetPasswordRSAPublicKey", enc.Bytes(), true)
	if err != nil {
		return "", "", 0, err
	}

	// Decode response
	dec := NewSimpleProtoDecoder(respData)
	for {
		fieldNum, wireType, err := dec.ReadField()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", 0, err
		}

		switch fieldNum {
		case 1: // publickey_mod
			mod, _ = dec.ReadString()
		case 2: // publickey_exp
			exp, _ = dec.ReadString()
		case 3: // timestamp
			timestamp, _ = dec.ReadUint64()
		default:
			dec.Skip(wireType)
		}
	}

	return mod, exp, timestamp, nil
}

// BeginAuthSession starts an authentication session
func (c *SimpleAuthClient) BeginAuthSession(
	accountName, encryptedPassword string,
	encryptionTimestamp uint64,
	guardData string,
) (clientID uint64, requestID []byte, interval float32, steamID uint64, err error) {

	// Encode device details submessage
	deviceEnc := NewSimpleProtoEncoder()
	deviceEnc.WriteString(1, "go-steam")     // device_friendly_name
	deviceEnc.WriteUint32(2, 1)              // platform_type = SteamClient
	deviceEnc.WriteInt32(3, -500)            // os_type = Unknown
	deviceEnc.WriteUint32(4, 1)              // gaming_device_type = Desktop

	// Encode main request
	enc := NewSimpleProtoEncoder()
	enc.WriteString(1, "go-steam")            // device_friendly_name (deprecated)
	enc.WriteString(2, accountName)           // account_name
	enc.WriteString(3, encryptedPassword)     // encrypted_password
	enc.WriteUint64(4, encryptionTimestamp)   // encryption_timestamp
	enc.WriteBool(5, true)                    // remember_login
	enc.WriteUint32(6, 1)                     // platform_type = SteamClient
	enc.WriteUint32(7, 1)                     // persistence = Persistent
	enc.WriteString(8, "Client")              // website_id
	enc.WriteMessage(9, deviceEnc.Bytes())    // device_details
	if guardData != "" {
		enc.WriteString(10, guardData)        // guard_data
	}
	enc.WriteInt32(12, 2)                     // qos_level

	respData, err := c.callAPI("IAuthenticationService", "BeginAuthSessionViaCredentials", enc.Bytes(), false)
	if err != nil {
		return 0, nil, 0, 0, err
	}

	// Decode response
	dec := NewSimpleProtoDecoder(respData)
	for {
		fieldNum, wireType, err := dec.ReadField()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, nil, 0, 0, err
		}

		switch fieldNum {
		case 1: // client_id
			clientID, _ = dec.ReadUint64()
		case 2: // request_id
			requestID, _ = dec.ReadBytes()
		case 3: // interval
			interval, _ = dec.ReadFloat32()
		case 5: // steamid
			steamID, _ = dec.ReadUint64()
		default:
			dec.Skip(wireType)
		}
	}

	return clientID, requestID, interval, steamID, nil
}

// PollAuthSessionStatus polls authentication status
func (c *SimpleAuthClient) PollAuthSessionStatus(clientID uint64, requestID []byte) (
	refreshToken, accessToken, newGuardData, accountName string, err error) {

	// Encode request
	enc := NewSimpleProtoEncoder()
	enc.WriteUint64(1, clientID)
	enc.WriteBytes(2, requestID)

	respData, err := c.callAPI("IAuthenticationService", "PollAuthSessionStatus", enc.Bytes(), false)
	if err != nil {
		return "", "", "", "", err
	}

	// Decode response
	dec := NewSimpleProtoDecoder(respData)
	for {
		fieldNum, wireType, err := dec.ReadField()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", "", "", err
		}

		switch fieldNum {
		case 3: // refresh_token
			refreshToken, _ = dec.ReadString()
		case 4: // access_token
			accessToken, _ = dec.ReadString()
		case 6: // account_name
			accountName, _ = dec.ReadString()
		case 7: // new_guard_data
			newGuardData, _ = dec.ReadString()
		default:
			dec.Skip(wireType)
		}
	}

	return refreshToken, accessToken, newGuardData, accountName, nil
}

// UpdateAuthSessionWithSteamGuardCode submits a Steam Guard code for authentication
func (c *SimpleAuthClient) UpdateAuthSessionWithSteamGuardCode(
	clientID uint64,
	steamID uint64,
	code string,
	codeType int32,
) error {
	fmt.Printf("DEBUG: UpdateAuthSessionWithSteamGuardCode:\n")
	fmt.Printf("  ClientID: %d\n", clientID)
	fmt.Printf("  SteamID: %d\n", steamID)
	fmt.Printf("  Code: %s\n", code)
	fmt.Printf("  CodeType: %d\n", codeType)

	// Encode request
	enc := NewSimpleProtoEncoder()
	enc.WriteUint64(1, clientID)    // client_id (uint64)
	enc.WriteFixed64(2, steamID)    // steamid (fixed64) - 这里很重要！
	enc.WriteString(3, code)        // code
	enc.WriteInt32(4, codeType)     // code_type

	respData, err := c.callAPI("IAuthenticationService", "UpdateAuthSessionWithSteamGuardCode", enc.Bytes(), false)
	if err != nil {
		return err
	}

	fmt.Printf("DEBUG: Response length: %d bytes\n", len(respData))
	return nil
}
