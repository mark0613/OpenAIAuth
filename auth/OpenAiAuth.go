package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
)

type Error struct {
	Location   string
	StatusCode int
	Details    string
}

func NewError(location string, statusCode int, details string) *Error {
	return &Error{
		Location:   location,
		StatusCode: statusCode,
		Details:    details,
	}
}

type AccountCookies map[string][]*http.Cookie

var allCookies AccountCookies

type Result struct {
	AccessToken string `json:"access_token"`
	PUID        string `json:"puid"`
	TeamUserID  string `json:"team_uid,omitempty"`
}

const (
	defaultErrorMessageKey             = "errorMessage"
	AuthorizationHeader                = "Authorization"
	XAuthorizationHeader               = "X-Authorization"
	ContentType                        = "application/x-www-form-urlencoded"
	Auth0Url                           = "https://auth.openai.com"
	LoginPasswordUrl                   = "https://auth0.openai.com/u/login/password?state="
	ParseUserInfoErrorMessage          = "Failed to parse user login info."
	SendOTPUrl                         = "https://api.openai.com/dashboard/onboarding/email-otp/send"
	OTPUrl                             = "https://api.openai.com/dashboard/onboarding/email-otp/validate"
	GetAuthorizedUrlErrorMessage       = "Failed to get authorized url."
	GetStateErrorMessage               = "Failed to get state."
	SendOTPErrorMessage                = "Failed to send OTP."
	EmailOrPasswordInvalidErrorMessage = "Email or password is not correct."
	GetAccessTokenErrorMessage         = "Failed to get access token."
	GetArkoseTokenErrorMessage         = "Failed to get arkose token."
	defaultTimeoutSeconds              = 600 // 10 minutes

	csrfUrl                  = "https://chatgpt.com/api/auth/csrf"
	promptLoginUrl           = "https://chatgpt.com/api/auth/signin/openai?prompt=login&screen_hint=login&ext-login-allow-phone=true&ext-oai-did="
	getCsrfTokenErrorMessage = "Failed to get CSRF token."
	authSessionUrl           = "https://chatgpt.com/api/auth/session"
)

var u, _ = url.Parse("https://chatgpt.com")
var UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
var clientProfile profiles.ClientProfile = profiles.Okhttp4Android13
var tempDID string
var lastURL string

type UserLogin struct {
	Username string
	Password string
	client   tls_client.HttpClient
	Result   Result
}

func init() {
	envUserAgent := os.Getenv("UA")
	if envUserAgent != "" {
		UserAgent = envUserAgent
	}
	envClientProfileStr := os.Getenv("CLIENT_PROFILE")
	if profile, ok := profiles.MappedTLSClients[envClientProfileStr]; ok {
		clientProfile = profile
	}
}

//goland:noinspection GoUnhandledErrorResult,SpellCheckingInspection
func NewHttpClient(proxyUrl string) tls_client.HttpClient {
	client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithTimeoutSeconds(600),
		tls_client.WithClientProfile(clientProfile),
		tls_client.WithCustomRedirectFunc(func(req *http.Request, via []*http.Request) error {
			lastURL = req.URL.String()
			return nil // 返回 nil 继续重定向
		}),
	}...)
	if proxyUrl != "" {
		client.SetProxy(proxyUrl)
	}
	return client
}

func NewAuthenticator(emailAddress, password, proxy string) *UserLogin {
	userLogin := &UserLogin{
		Username: emailAddress,
		Password: password,
		client:   NewHttpClient(proxy),
	}
	return userLogin
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) GetAuthorizedUrl(csrfToken string) (string, int, error) {
	form := url.Values{
		"callbackUrl": {"/"},
		"csrfToken":   {csrfToken},
		"json":        {"true"},
	}
	req, err := http.NewRequest(http.MethodPost, promptLoginUrl+tempDID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, errors.New(GetAuthorizedUrlErrorMessage)
	}

	responseMap := make(map[string]string)
	json.NewDecoder(resp.Body).Decode(&responseMap)
	req, err = http.NewRequest(http.MethodGet, responseMap["url"], nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Referer", "https://chatgpt.com/")
	resp, err = userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, errors.New(GetAuthorizedUrlErrorMessage)
	}
	return lastURL, http.StatusOK, nil
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) CheckUsername(authorizedUrl string, username string) (string, int, error) {
	u, _ := url.Parse(authorizedUrl)
	query := u.Query()
	query.Del("prompt")
	query.Set("max_age", "0")
	query.Set("ext-login-hint-email", username)
	query.Set("login_hint", username)
	query.Set("idp", "auth0")
	query.Set("ext-oai-did-source", "web")
	req, _ := http.NewRequest(http.MethodGet, Auth0Url+"/api/accounts/authorize?"+query.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		u, _ = url.Parse(lastURL)
		query = u.Query()
		state := query.Get("state")
		return state, http.StatusOK, nil
	} else {
		return "", http.StatusInternalServerError, errors.New(GetStateErrorMessage)
	}
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) CheckPassword(state string, username string, password string) (string, int, error) {
	formParams := url.Values{
		"state":    {state},
		"username": {username},
		"password": {password},
	}
	req, err := http.NewRequest(http.MethodPost, LoginPasswordUrl+state, strings.NewReader(formParams.Encode()))
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, errors.New(EmailOrPasswordInvalidErrorMessage)
	}
	if strings.Contains(lastURL, "/login_challenge") {
		u, _ := url.Parse(lastURL)
		query := u.Query()
		auth0Token := query.Get("auth0_token")
		auth0State := query.Get("state")
		req, err := http.NewRequest(http.MethodPost, SendOTPUrl, bytes.NewBuffer([]byte(`{"auth0-token":"`+auth0Token+`","use_fallback_email_provider":false}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("Referer", "https://auth.openai.com/")
		resp, err := userLogin.client.Do(req)
		if err != nil {
			return "", http.StatusInternalServerError, err
		}
		if resp.StatusCode != http.StatusNoContent {
			return "", resp.StatusCode, errors.New(SendOTPErrorMessage)
		}
	validate:
		fmt.Print("Log-in Code of " + username + ": ")
		var input string
		fmt.Scanln(&input)
		req, err = http.NewRequest(http.MethodPost, OTPUrl, bytes.NewBuffer([]byte(`{"auth0-token":"`+auth0Token+`","auth0-state":"`+auth0State+`","code":"`+input+`"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("Referer", "https://auth.openai.com/")
		resp, err = userLogin.client.Do(req)
		if err != nil {
			return "", http.StatusInternalServerError, err
		}
		if resp.StatusCode == http.StatusOK {
			responseMap := make(map[string]string)
			json.NewDecoder(resp.Body).Decode(&responseMap)
			req, _ = http.NewRequest(http.MethodGet, responseMap["redirect_url"], nil)
			req.Header.Set("User-Agent", UserAgent)
			req.Header.Set("Referer", "https://auth.openai.com/")
			resp, err = userLogin.client.Do(req)
			if err != nil {
				return "", http.StatusInternalServerError, err
			}
			defer resp.Body.Close()
		} else if resp.StatusCode == http.StatusUnauthorized {
			fmt.Println("Log-in Code error, try again")
			goto validate
		} else if resp.StatusCode == http.StatusTooManyRequests {
			fmt.Println("Exceed rate limit, try again later")
			goto validate
		}
	}

	return "", resp.StatusCode, nil
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat,GoUnusedParameter
func (userLogin *UserLogin) GetAccessTokenInternal(code string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, authSessionUrl, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			responseMap := make(map[string]string)
			json.NewDecoder(resp.Body).Decode(&responseMap)
			return "", resp.StatusCode, errors.New(responseMap["detail"])
		}

		return "", resp.StatusCode, errors.New(GetAccessTokenErrorMessage)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, err
	}
	// Check if access token in data
	if _, ok := result["accessToken"]; !ok {
		result_string := fmt.Sprintf("%v", result)
		return result_string, 0, errors.New("missing access token")
	}
	return result["accessToken"].(string), http.StatusOK, nil
}

func (userLogin *UserLogin) Begin() *Error {
	_, err, token := userLogin.GetToken()
	if err != "" {
		return NewError("begin", 0, err)
	}
	userLogin.Result.AccessToken = token
	return nil
}

func (userLogin *UserLogin) GetToken() (int, string, string) {
	// get csrf token
	req, _ := http.NewRequest(http.MethodGet, csrfUrl, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return http.StatusInternalServerError, err.Error(), ""
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, getCsrfTokenErrorMessage, ""
	}

	// get authorized url
	responseMap := make(map[string]string)
	json.NewDecoder(resp.Body).Decode(&responseMap)
	authorizedUrl, statusCode, err := userLogin.GetAuthorizedUrl(responseMap["csrfToken"])
	if err != nil {
		return statusCode, err.Error(), ""
	}

	// check username
	state, statusCode, err := userLogin.CheckUsername(authorizedUrl, userLogin.Username)
	if err != nil {
		return statusCode, err.Error(), ""
	}

	// check password
	_, statusCode, err = userLogin.CheckPassword(state, userLogin.Username, userLogin.Password)
	if err != nil {
		return statusCode, err.Error(), ""
	}

	// get access token
	accessToken, statusCode, err := userLogin.GetAccessTokenInternal("")
	if err != nil {
		return statusCode, err.Error(), ""
	}

	return http.StatusOK, "", accessToken
}

func (userLogin *UserLogin) GetAccessToken() string {
	return userLogin.Result.AccessToken
}

func (userLogin *UserLogin) GetPUID() (string, *Error) {
	// Check if user has access token
	if userLogin.Result.AccessToken == "" {
		return "", NewError("get_puid", 0, "Missing access token")
	}
	// Make request to https://chatgpt.com/backend-api/models
	req, _ := http.NewRequest("GET", "https://chatgpt.com/backend-api/models?history_and_training_disabled=false", nil)
	// Add headers
	req.Header.Add("Authorization", "Bearer "+userLogin.Result.AccessToken)
	req.Header.Add("User-Agent", UserAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", NewError("get_puid", 0, "Failed to make request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", NewError("get_puid", resp.StatusCode, "Failed to make request")
	}
	// Find `_puid` cookie in response
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "_puid" {
			userLogin.Result.PUID = cookie.Value
			return cookie.Value, nil
		}
	}
	// If cookie not found, return error
	return "", NewError("get_puid", 0, "PUID cookie not found")
}

type AccountInfo struct {
	Account struct {
		AccountId   string `json:"account_id"`
		PlanType    string `json:"plan_type"`
		Deactivated bool   `json:"is_deactivated"`
	} `json:"account"`
}
type UserID struct {
	Accounts map[string]AccountInfo `json:"accounts"`
}

func (userLogin *UserLogin) GetTeamUserID() (string, *Error) {
	// Check if user has access token
	if userLogin.Result.AccessToken == "" {
		return "", NewError("get_teamuserid", 0, "Missing access token")
	}
	req, _ := http.NewRequest("GET", "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27", nil)
	// Add headers
	req.Header.Add("Authorization", "Bearer "+userLogin.Result.AccessToken)
	req.Header.Add("User-Agent", UserAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", NewError("get_teamuserid", 0, "Failed to make request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", NewError("get_teamuserid", resp.StatusCode, "Failed to make request")
	}
	var userId UserID
	err = json.NewDecoder(resp.Body).Decode(&userId)
	if err != nil {
		return "", NewError("get_teamuserid", 0, "teamuserid not found")
	}
	for _, item := range userId.Accounts {
		if item.Account.PlanType == "team" && !item.Account.Deactivated {
			userLogin.Result.TeamUserID = item.Account.AccountId
			return item.Account.AccountId, nil
		}
	}
	// If cookie not found, return error
	return "", NewError("get_teamuserid", 0, "teamuserid not found")
}

func init() {
	allCookies = AccountCookies{}
	file, err := os.Open("cookies.json")
	if err != nil {
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&allCookies)
	if err != nil {
		return
	}
}

func (userLogin *UserLogin) ResetCookies() {
	tempDID = uuid.NewString()
	newCookies := tls_client.NewCookieJar()
	newCookies.SetCookies(u, []*http.Cookie{{
		Name:    "oai-did",
		Value:   tempDID,
		Expires: time.Now().Add(time.Hour * 24 * 365),
	}})
	userLogin.client.SetCookieJar(newCookies)
}

func (userLogin *UserLogin) SaveCookies() *Error {
	if len(allCookies[userLogin.Username]) != 0 && allCookies[userLogin.Username][0].Name == "refresh_token" {
		return nil
	}
	cookies := userLogin.client.GetCookieJar().Cookies(u)
	file, err := os.OpenFile("cookies.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return NewError("saveCookie", 0, err.Error())
	}
	defer file.Close()
	filtered := []*http.Cookie{}
	expireTime := time.Now().AddDate(0, 0, 7)
	for _, cookie := range cookies {
		if cookie.Expires.After(expireTime) {
			filtered = append(filtered, cookie)
		}
	}
	allCookies[userLogin.Username] = filtered
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(allCookies)
	if err != nil {
		return NewError("saveCookie", 0, err.Error())
	}
	return nil
}

func (userLogin *UserLogin) RefreshIOSToken(refreshToken string) (string, *Error) {
	data := map[string]interface{}{
		"redirect_uri":  "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
		"grant_type":    "refresh_token",
		"client_id":     "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
		"refresh_token": refreshToken,
	}
	jsonData, _ := json.Marshal(data)

	req, _ := http.NewRequest(http.MethodPost, "https://auth0.openai.com/oauth/token", bytes.NewBuffer(jsonData))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", NewError("refreshIOSToken", 0, err.Error())
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", NewError("refreshIOSToken", 0, "response StatusCode not OK")
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", NewError("refreshIOSToken", 0, err.Error())
	}
	// Check if access token in data
	if _, ok := result["access_token"]; !ok {
		return "", NewError("refreshIOSToken", 0, "missing access token")
	}
	return result["access_token"].(string), nil
}

func (userLogin *UserLogin) RenewWithCookies() *Error {
	cookies := allCookies[userLogin.Username]
	if len(cookies) == 0 {
		return NewError("readCookie", 0, "no cookies")
	}
	if cookies[0].Name == "refresh_token" {
		userLogin.ResetCookies()
		accessToken, err := userLogin.RefreshIOSToken(cookies[0].Value)
		if err != nil {
			return err
		}
		userLogin.Result.AccessToken = accessToken
		return nil
	} else {
		userLogin.client.GetCookieJar().SetCookies(u, cookies)
		accessToken, statusCode, err := userLogin.GetAccessTokenInternal("")
		if err != nil {
			return NewError("renewToken", statusCode, err.Error())
		}
		userLogin.Result.AccessToken = accessToken
		return nil
	}
}

func (userLogin *UserLogin) GetAuthResult() Result {
	return userLogin.Result
}
