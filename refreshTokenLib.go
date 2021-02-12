//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// Laravel              - https://laravel.com
// Laravel Passport     - https://laravel.com/docs/passport
// League OAuth2 server - https://github.com/thephpleague/oauth2-server
// access_token         - https://github.com/lcobucci/jwt
// refresh_token        - https://github.com/defuse/php-encryption
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
package refreshTokenLib
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
import (
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/hkdf"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"errors"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"bufio"
	"bytes"
	"encoding/json"
	"github.com/progman/libcore.go"
)
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
const HEADER_VERSION_SIZE        int    = 4
const MINIMUM_CIPHERTEXT_SIZE    int    = 84
const CURRENT_VERSION            string = "\xDE\xF5\x02\x00"
const SALT_BYTE_SIZE             int    = 32
const BLOCK_BYTE_SIZE            int    = 16
const MAC_BYTE_SIZE              int    = 32
const PBKDF2_ITERATIONS          int    = 100000
const KEY_BYTE_SIZE              int    = 32
const ENCRYPTION_INFO_STRING     string = "DefusePHP|V2|KeyForEncryption";
const AUTHENTICATION_INFO_STRING string = "DefusePHP|V2|KeyForAuthentication";
const CIPHER_METHOD              string = "aes-256-ctr"
const HASH_FUNCTION_NAME         string = "sha256"
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * body of refresh token
 */
type RefreshTokenBody struct {
	Iss            string   `json:"iss"`              // issuer (a person or company that supplies or distributes something) - maker, https://tools.ietf.org/html/rfc7519#section-4.1.1
	ClientID       string   `json:"client_id"`        // client_id,                                                                   https://tools.ietf.org/html/rfc7519#section-4.1.3
	RefreshTokenID string   `json:"refresh_token_id"` // refresh_token_id
	AccessTokenID  string   `json:"access_token_id"`  // access_token_id,                                                             https://tools.ietf.org/html/rfc7519#section-4.1.7
	Scopes         []string `json:"scopes"`           // ["api","paymentapi"]
	UserID         string   `json:"user_id"`          // user_id,                                                                     https://tools.ietf.org/html/rfc7519#section-4.1.2
	ExpireTime     int      `json:"expire_time"`      // time to stop to work (delete if too far of this time),                       https://tools.ietf.org/html/rfc7519#section-4.1.4
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * simple show of body of refresh token
 */
func (p *RefreshTokenBody) Show() {
	fmt.Printf("Iss:            \"%s\"\n", p.Iss)
	fmt.Printf("ClientID:       \"%s\"\n", p.ClientID)
	fmt.Printf("RefreshTokenID: \"%s\"\n", p.RefreshTokenID)
	fmt.Printf("AccessTokenID:  \"%s\"\n", p.AccessTokenID)

	fmt.Printf("Scopes:         [ ")
	for i := 0; i < len(p.Scopes); i++ {
		if i != 0 {
			fmt.Printf(", ")
		}
		fmt.Printf("\"%s\"", p.Scopes[i])
	}
	fmt.Printf(" ]\n")

	fmt.Printf("UserID:         \"%s\"\n", p.UserID)
	fmt.Printf("ExpireTime:     %d\n", p.ExpireTime)
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * refresh token lib class
 */
type RefreshTokenLib struct {
	password     []byte
	flagPassword bool
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * init refresh token lib object
 */
func (p *RefreshTokenLib) Init() {
	p.flagPassword = false
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * aes encrypt/decrypt
 * \param[in] source encrypted/decrypted data
 * \param[in] key key for encrypt/decrypt
 * \param[in] iv iv for encrypt/decrypt
 * \return target encrypted/decrypted data
 * \return err error
 */
func (p *RefreshTokenLib) doCrypt(source []byte, key []byte, iv []byte) (target []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return target, err
	}


	target = make([]byte, len(source))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(target, source)


	return target, err
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * aes decrypt
 * \param[in] source encrypted refresh token
 * \param[in] password password
 * \return target decrypted refresh token
 * \return err error
 */
func (p *RefreshTokenLib) decrypt(source []byte, password []byte) (target []byte, err error) {

	if CIPHER_METHOD != "aes-256-ctr" {
		err = errors.New("invalid cipher method")
		return
	}
	if HASH_FUNCTION_NAME != "sha256" {
		err = errors.New("invalid hash function")
		return
	}


// decode from hex to bin form
	source_bin, err := hex.DecodeString(string(source))
	if err != nil {
		return
	}


// chech size
	if len(source_bin) < MINIMUM_CIPHERTEXT_SIZE {
		err = errors.New("invalid source length")
		return
	}


// get header
	header := libcore.SubByte(source_bin, 0, HEADER_VERSION_SIZE)
	rc := bytes.Compare(header, []byte(CURRENT_VERSION))
	if rc != 0 {
		err = errors.New("header is not correct")
		return
	}


// get salt
	salt := libcore.SubByte(source_bin, HEADER_VERSION_SIZE, SALT_BYTE_SIZE)
	if len(salt) != SALT_BYTE_SIZE {
		err = errors.New("salt is not correct")
		return
	}


// get iv (initial vector)
	iv := libcore.SubByte(source_bin, HEADER_VERSION_SIZE + SALT_BYTE_SIZE, BLOCK_BYTE_SIZE)


// get mac (message authentication code)
	mac := libcore.SubByte(source_bin, len(source_bin) - MAC_BYTE_SIZE, MAC_BYTE_SIZE)


// get encrypted
	encrypted := libcore.SubByte(source_bin, HEADER_VERSION_SIZE + SALT_BYTE_SIZE + BLOCK_BYTE_SIZE, len(source_bin) - MAC_BYTE_SIZE - SALT_BYTE_SIZE - BLOCK_BYTE_SIZE - HEADER_VERSION_SIZE)


// get prehash
	h := sha256.New()
	h.Write(password)
	prehash := h.Sum(nil)


// get prekey
	prekey := pbkdf2.Key(prehash, salt, PBKDF2_ITERATIONS, KEY_BYTE_SIZE, sha256.New)


// get akey
	hkdf_a := hkdf.New(sha256.New, prekey, salt, []byte(AUTHENTICATION_INFO_STRING))
	akey := make([]byte, 32)
	_, err = io.ReadFull(hkdf_a, akey)
	if err != nil {
		return
	}


// get ekey
	hkdf_e := hkdf.New(sha256.New, prekey, salt, []byte(ENCRYPTION_INFO_STRING))
	ekey := make([]byte, 32)
	_, err = io.ReadFull(hkdf_e, ekey)
	if err != nil {
		return
	}


// check mac
	hmac_obj := hmac.New(sha256.New, akey)
	hmac_obj.Write(header)
	hmac_obj.Write(salt)
	hmac_obj.Write(iv)
	hmac_obj.Write(encrypted)
	expectedMAC := hmac_obj.Sum(nil)
	if hmac.Equal(mac, expectedMAC) == false {
		err = errors.New("mac is broken")
		return
	}


// decrypt
	target, err = p.doCrypt(encrypted, ekey, iv)
	if err != nil {
		return
	}


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * aes encrypt
 * \param[in] source decrypted refresh token
 * \param[in] password password
 * \return target ecrypted refresh token
 * \return err error
 */
func (p *RefreshTokenLib) encrypt(source []byte, password []byte) (target []byte, err error) {

	if CIPHER_METHOD != "aes-256-ctr" {
		err = errors.New("invalid cipher method")
		return
	}
	if HASH_FUNCTION_NAME != "sha256" {
		err = errors.New("invalid hash function")
		return
	}


// get salt
	salt := make([]byte, SALT_BYTE_SIZE)
	_, err = rand.Read(salt)
	if err != nil {
		return
	}


// get iv (initial vector)
	iv := make([]byte, BLOCK_BYTE_SIZE)
	_, err = rand.Read(iv)
	if err != nil {
		return
	}


// get prehash
	h := sha256.New()
	h.Write(password)
	prehash := h.Sum(nil)


// get prekey
	prekey := pbkdf2.Key(prehash, salt, PBKDF2_ITERATIONS, KEY_BYTE_SIZE, sha256.New)


// get akey
	hkdf_a := hkdf.New(sha256.New, prekey, salt, []byte(AUTHENTICATION_INFO_STRING))
	akey := make([]byte, 32)
	_, err = io.ReadFull(hkdf_a, akey)
	if err != nil {
		return
	}


// get ekey
	hkdf_e := hkdf.New(sha256.New, prekey, salt, []byte(ENCRYPTION_INFO_STRING))
	ekey := make([]byte, 32)
	_, err = io.ReadFull(hkdf_e, ekey)
	if err != nil {
		return
	}


// encrypt
	encrypted, err := p.doCrypt([]byte(source), ekey, iv)
	if err != nil {
		return
	}
	target = append(target, CURRENT_VERSION...)
	target = append(target, salt...)
	target = append(target, iv...)
	target = append(target, encrypted...)


// add mac (message authentication code)
	hmac_obj := hmac.New(sha256.New, akey)
	hmac_obj.Write(target)
	mac := hmac_obj.Sum(nil)
	target = append(target, mac...)


// encode to hex
	target = []byte(hex.EncodeToString(target))


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * load password for decode/encode from file
 * \param[in] path path of password (password maybe in base64 or hex form like base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=)
 * \return err error
 */
func (p *RefreshTokenLib) LoadPassword(path string) (err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}


// get first line from file
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		break
	}


	return p.SetPassword(line)
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * set password for decode/encode
 * \param[in] source password (maybe in base64 or hex form like base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=)
 * \return token access token
 * \return err error
 */
func (p *RefreshTokenLib) SetPassword(source string) (err error) {
	const token1 = "base64:"
	const token2 = "hex:"


	if strings.Index(source, token1) == 0 {
		source = libcore.SubStr(source, len(token1), -1)
		p.password, err = base64.StdEncoding.DecodeString(source)
		if err != nil {
			p.flagPassword = true
		}
		return
	}


	if strings.Index(source, token2) == 0 {
		source = libcore.SubStr(source, len(token2), -1)
		p.password, err = base64.StdEncoding.DecodeString(source)
		if err != nil {
			p.flagPassword = true
		}
		return
	}


	p.password     = []byte(source)
	p.flagPassword = true


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * decode refresh token to RefreshTokenBody object
 * \param[in] pRefreshTokenBody pointer to RefreshTokenBody object
 * \param[in] token encripted refresh token
 * \return err error
 */
func (p *RefreshTokenLib) Decode(pRefreshTokenBody *RefreshTokenBody, token []byte) (err error) {
	data, err := p.decrypt(token, p.password)
	if err != nil {
		return
	}


/*
	err = json.Unmarshal(data, pRefreshTokenBody)
	if err != nil {
		return
	}
*/


// user_id can be type of INT or STRING so decode it careful
	var objMap map[string]json.RawMessage
	err = json.Unmarshal([]byte(data), &objMap)
	if err != nil {
		return
	}


	for k := range objMap {
		switch k {
			case "iss": {
				err = json.Unmarshal(objMap["iss"], &pRefreshTokenBody.Iss)
				if err != nil {
					return
				}
			}

			case "client_id": {
				err = json.Unmarshal(objMap["client_id"], &pRefreshTokenBody.ClientID)
				if err != nil {
					return
				}
			}

			case "refresh_token_id": {
				err = json.Unmarshal(objMap["refresh_token_id"], &pRefreshTokenBody.RefreshTokenID)
				if err != nil {
					return
				}
			}

			case "access_token_id": {
				err = json.Unmarshal(objMap["access_token_id"], &pRefreshTokenBody.AccessTokenID)
				if err != nil {
					return
				}
			}

			case "scopes": {
				err = json.Unmarshal(objMap["scopes"], &pRefreshTokenBody.Scopes)
				if err != nil {
					return
				}
			}

			case "user_id": {
				err = json.Unmarshal(objMap["user_id"], &pRefreshTokenBody.UserID)
				if err != nil {
					var UserID int
					err = json.Unmarshal(objMap["user_id"], &UserID)
					if err != nil {
						return
					}
					pRefreshTokenBody.UserID = fmt.Sprintf("%d", UserID)
				}
			}

			case "expire_time": {
				err = json.Unmarshal(objMap["expire_time"], &pRefreshTokenBody.ExpireTime)
				if err != nil {
					return
				}
			}

			default: {
				err = errors.New("parse error, unknown key")
				return
			}
		}
	}


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * encode RefreshTokenBody object to refresh token
 * \param[in] pRefreshTokenBody pointer to RefreshTokenBody object
 * \return token encripted refresh token
 * \return err error
 */
func (p *RefreshTokenLib) Encode(pRefreshTokenBody *RefreshTokenBody) (token []byte, err error) {
	data, err := json.Marshal(pRefreshTokenBody)
	if err != nil {
		return
	}


	token, err = p.encrypt(data, p.password)
	if err != nil {
		return
	}


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
