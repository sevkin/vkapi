package vkapi

import (
	"encoding/json"
	"errors"
	"strconv"

	resty "gopkg.in/resty.v1"
)

const (
	endpointAuthDirect = "https://oauth.vk.com/token"
	oauthVsn           = "5.40"
)

// прямая авторизация
// получение токена, прикидываясь офциальным приложением
// https://vk.com/dev/auth_direct

// "примеры" приложений
// https://toster.ru/answer?answer_id=1075698

// TODO: change user-agent, support proxy, handle captcha, handle redirect

// AuthDirect return token
func AuthDirect(client uint, secret, username, password string) (string, error) {
	response, err := resty.R().SetQueryParams(map[string]string{
		"grant_type":    "password",
		"client_id":     strconv.FormatUint(uint64(client), 10),
		"client_secret": secret,
		"username":      username,
		"password":      password,
		"v":             oauthVsn,
	}).Get(endpointAuthDirect)
	if err != nil {
		return "", err
	}

	var token struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		// ExpiresIn   uint   `json:"expires_in"`
		// UserID      uint   `json:"user_id"`
		// CaptchaSID  uint   `json:"captcha_sid"`
		// CaptchaImg  string `json:"captcha_img"`
		// RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(response.Body(), &token); err != nil {
		return "", err
	}

	if token.Error != "" {
		return "", errors.New(response.String()) // raw json on error
	}

	if token.AccessToken == "" {
		return "", errors.New(response.String()) // raw json on no access_token
	}

	return token.AccessToken, nil
}
