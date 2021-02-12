package refreshTokenLib // killme and uncomment example
/*
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
package main
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
import (
	"fmt"
	"os"
	"github.com/progman/refreshTokenLib.go"
)
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
func main() {
	var err error
	var rtl refreshTokenLib.RefreshTokenLib
	rtl.Init()


// set password
	err = rtl.LoadPassword("resource/oauth-password.cfg")
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}


// prepare refresh token body
	var refreshTokenBody refreshTokenLib.RefreshTokenBody
	refreshTokenBody.Iss            = ""
	refreshTokenBody.ClientID       = "2"
	refreshTokenBody.RefreshTokenID = "2050aad8f414875a338e2595ffce4900027ed51869ab4ab56c829c70432edd295a5996487b04bfba"
	refreshTokenBody.AccessTokenID  = "6c2fc5e3c7f5fd944203b94418263cac4575ffd4d5ab69230938d434f3d7297701a3e700026d4e92"
	refreshTokenBody.Scopes         = append(refreshTokenBody.Scopes, "api")
	refreshTokenBody.Scopes         = append(refreshTokenBody.Scopes, "paymentapi")
	refreshTokenBody.UserID         = "16"
	refreshTokenBody.ExpireTime     = 1609928111


// show refresh token body
	refreshTokenBody.Show()


// encode refresh token
	fmt.Printf("\n --- Encode...\n")
	refresh_token, err := rtl.Encode(&refreshTokenBody)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}


// show refresh token
	fmt.Printf("refresh token: %s\n", string(refresh_token))


// decode refresh token
	fmt.Printf("\n --- Decode...\n")
	err = rtl.Decode(&refreshTokenBody, refresh_token)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}


// show refresh token body
	refreshTokenBody.Show()


	os.Exit(0)
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
*/
