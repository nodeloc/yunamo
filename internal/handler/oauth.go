package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	oauthGithub "golang.org/x/oauth2/github"
	"gorm.io/gorm"

	"opendomain/internal/config"
	"opendomain/internal/models"
	"opendomain/pkg/timeutil"
)

// OAuthHandler OAuth 处理器
type OAuthHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

// NewOAuthHandler 创建 OAuth 处理器
func NewOAuthHandler(db *gorm.DB, cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{db: db, cfg: cfg}
}

func (h *OAuthHandler) githubOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.cfg.OAuth.GithubClientID,
		ClientSecret: h.cfg.OAuth.GithubClientSecret,
		Scopes:       []string{"user:email"},
		Endpoint:     oauthGithub.Endpoint,
	}
}

func (h *OAuthHandler) googleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.cfg.OAuth.GoogleClientID,
		ClientSecret: h.cfg.OAuth.GoogleClientSecret,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		RedirectURL: fmt.Sprintf("%s/api/auth/google/callback", h.getBackendURL()),
	}
}

func (h *OAuthHandler) getBackendURL() string {
	// 使用 FRONTEND_URL，移除尾部斜杠
	baseURL := h.cfg.FrontendURL
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	return baseURL
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GithubLogin 发起 GitHub OAuth
func (h *OAuthHandler) GithubLogin(c *gin.Context) {
	if h.cfg.OAuth.GithubClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "GitHub OAuth not configured"})
		return
	}

	state := generateState()
	c.SetCookie("oauth_state", state, 600, "/", "", false, true)

	cfg := h.githubOAuthConfig()
	cfg.RedirectURL = fmt.Sprintf("%s/api/auth/github/callback", h.getBackendURL())

	url := cfg.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// GithubCallback 处理 GitHub OAuth 回调
func (h *OAuthHandler) GithubCallback(c *gin.Context) {
	// 验证 state
	state, _ := c.Cookie("oauth_state")
	if state == "" || state != c.Query("state") {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=invalid_state", h.cfg.FrontendURL))
		return
	}

	code := c.Query("code")
	if code == "" {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=no_code", h.cfg.FrontendURL))
		return
	}

	cfg := h.githubOAuthConfig()
	cfg.RedirectURL = fmt.Sprintf("%s/api/auth/github/callback", h.getBackendURL())

	// 交换 code 获取 token
	token, err := cfg.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("GitHub OAuth exchange error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=exchange_failed", h.cfg.FrontendURL))
		return
	}

	// 获取用户信息
	githubUser, err := h.fetchGithubUser(token.AccessToken)
	if err != nil {
		fmt.Printf("GitHub fetch user error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=fetch_user_failed", h.cfg.FrontendURL))
		return
	}

	// 获取邮箱
	email := githubUser.Email
	if email == "" {
		email, err = h.fetchGithubEmail(token.AccessToken)
		if err != nil || email == "" {
			c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=no_email", h.cfg.FrontendURL))
			return
		}
	}

	// 查找或创建用户 (GitHub 默认 normal 等级)
	defaultLevel := "normal"
	defaultQuota := GetQuotaForLevel(h.db, defaultLevel)
	user, err := h.findOrCreateOAuthUser("github", fmt.Sprintf("%d", githubUser.ID), email, githubUser.Login, githubUser.AvatarURL, c.ClientIP(), defaultLevel, defaultQuota)
	if err != nil {
		fmt.Printf("OAuth find/create user error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=%s", h.cfg.FrontendURL, url.QueryEscape("create_user_failed: "+err.Error())))
		return
	}

	// 生成 JWT
	jwtToken, err := generateToken(user, h.cfg)
	if err != nil {
		fmt.Printf("OAuth generate token error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=%s", h.cfg.FrontendURL, url.QueryEscape("token_failed: "+err.Error())))
		return
	}

	c.Redirect(http.StatusFound, fmt.Sprintf("%s/auth/callback?token=%s", h.cfg.FrontendURL, jwtToken))
}

// GoogleLogin 发起 Google OAuth
func (h *OAuthHandler) GoogleLogin(c *gin.Context) {
	if h.cfg.OAuth.GoogleClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Google OAuth not configured"})
		return
	}

	state := generateState()
	c.SetCookie("oauth_state", state, 600, "/", "", false, true)

	cfg := h.googleOAuthConfig()
	url := cfg.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// GoogleCallback 处理 Google OAuth 回调
func (h *OAuthHandler) GoogleCallback(c *gin.Context) {
	// 验证 state
	state, _ := c.Cookie("oauth_state")
	if state == "" || state != c.Query("state") {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=invalid_state", h.cfg.FrontendURL))
		return
	}

	code := c.Query("code")
	if code == "" {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=no_code", h.cfg.FrontendURL))
		return
	}

	cfg := h.googleOAuthConfig()

	// 交换 code 获取 token
	token, err := cfg.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("Google OAuth exchange error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=exchange_failed", h.cfg.FrontendURL))
		return
	}

	// 获取用户信息
	googleUser, err := h.fetchGoogleUser(token.AccessToken)
	if err != nil {
		fmt.Printf("Google fetch user error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=fetch_user_failed", h.cfg.FrontendURL))
		return
	}

	if googleUser.Email == "" {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=no_email", h.cfg.FrontendURL))
		return
	}

	// 用户名：取邮箱前缀
	username := strings.Split(googleUser.Email, "@")[0]

	// 查找或创建用户 (Google 默认 normal 等级)
	defaultLevel := "normal"
	defaultQuota := GetQuotaForLevel(h.db, defaultLevel)
	user, err := h.findOrCreateOAuthUser("google", googleUser.Sub, googleUser.Email, username, googleUser.Picture, c.ClientIP(), defaultLevel, defaultQuota)
	if err != nil {
		fmt.Printf("OAuth find/create user error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=create_user_failed", h.cfg.FrontendURL))
		return
	}

	// 生成 JWT
	jwtToken, err := generateToken(user, h.cfg)
	if err != nil {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=token_failed", h.cfg.FrontendURL))
		return
	}

	c.Redirect(http.StatusFound, fmt.Sprintf("%s/auth/callback?token=%s", h.cfg.FrontendURL, jwtToken))
}

// syncNodelocLevel 同步 NodeLoc 等级。配额只按新旧等级基础配额的差值调整，
// 直接覆盖为等级配额会清掉优惠券、邀请等奖励的额度
func (h *OAuthHandler) syncNodelocLevel(user *models.User, userLevel string, quota int, updates map[string]interface{}) {
	updates["user_level"] = userLevel
	if user.UserLevel == userLevel {
		return
	}
	if delta := quota - GetQuotaForLevel(h.db, user.UserLevel); delta != 0 {
		updates["domain_quota"] = gorm.Expr("domain_quota + ?", delta)
	}
}

// findOrCreateOAuthUser 查找或创建 OAuth 用户
func (h *OAuthHandler) findOrCreateOAuthUser(provider, oauthID, email, username, avatar, clientIP, userLevel string, quota int) (*models.User, error) {
	var user models.User

	// 1. 先按 provider + oauth_id 查找
	err := h.db.Where("provider = ? AND oauth_id = ?", provider, oauthID).First(&user).Error
	if err == nil {
		// 已有 OAuth 用户，更新登录信息
		updates := map[string]interface{}{
			"last_login_at": timeutil.Now(),
			"last_login_ip": clientIP,
		}
		// NodeLoc 用户再次登录时更新等级和配额
		if provider == "nodeloc" {
			h.syncNodelocLevel(&user, userLevel, quota, updates)
		}
		h.db.Model(&user).Updates(updates)
		return &user, nil
	}

	// 2. 按邮箱查找已有用户
	err = h.db.Where("email = ?", email).First(&user).Error
	if err == nil {
		// 邮箱已存在，关联 OAuth
		updates := map[string]interface{}{
			"provider":      provider,
			"oauth_id":      oauthID,
			"last_login_at": timeutil.Now(),
			"last_login_ip": clientIP,
		}
		if provider == "nodeloc" {
			h.syncNodelocLevel(&user, userLevel, quota, updates)
		}
		h.db.Model(&user).Updates(updates)
		if avatar != "" && user.Avatar == nil {
			h.db.Model(&user).Update("avatar", avatar)
		}
		return &user, nil
	}

	// 3. 创建新用户
	inviteCode, err := generateInviteCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate invite code: %w", err)
	}

	// 确保用户名唯一
	finalUsername := username
	var count int64
	h.db.Model(&models.User{}).Where("username = ?", finalUsername).Count(&count)
	if count > 0 {
		suffix := make([]byte, 3)
		rand.Read(suffix)
		finalUsername = fmt.Sprintf("%s_%s", username, hex.EncodeToString(suffix))
	}

	now := timeutil.Now()
	newUser := &models.User{
		Username:      finalUsername,
		Email:         email,
		EmailVerified: true,
		Provider:      provider,
		OAuthID:       &oauthID,
		UserLevel:     userLevel,
		DomainQuota:   quota,
		Status:        "active",
		InviteCode:    inviteCode,
		LastLoginAt:   &now,
		LastLoginIP:   &clientIP,
	}
	if avatar != "" {
		newUser.Avatar = &avatar
	}

	if err := h.db.Create(newUser).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return newUser, nil
}

// GitHub API types
type githubUser struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (h *OAuthHandler) fetchGithubUser(accessToken string) (*githubUser, error) {
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var user githubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (h *OAuthHandler) fetchGithubEmail(accessToken string) (string, error) {
	req, _ := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var emails []githubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("no verified email found")
}

// Google API types
type googleUser struct {
	Sub     string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func (h *OAuthHandler) fetchGoogleUser(accessToken string) (*googleUser, error) {
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var user googleUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// NodeLoc OAuth

func (h *OAuthHandler) nodelocOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.cfg.OAuth.NodelocClientID,
		ClientSecret: h.cfg.OAuth.NodelocClientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.nodeloc.com/oauth-provider/authorize",
			TokenURL: "https://www.nodeloc.com/oauth-provider/token",
		},
		RedirectURL: fmt.Sprintf("%s/api/auth/nodeloc/callback", h.getBackendURL()),
	}
}

// NodelocLogin 发起 NodeLoc OAuth
func (h *OAuthHandler) NodelocLogin(c *gin.Context) {
	if h.cfg.OAuth.NodelocClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NodeLoc OAuth not configured"})
		return
	}

	state := generateState()
	c.SetCookie("oauth_state", state, 600, "/", "", false, true)

	cfg := h.nodelocOAuthConfig()
	authURL := cfg.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// NodelocCallback 处理 NodeLoc OAuth 回调
func (h *OAuthHandler) NodelocCallback(c *gin.Context) {
	state, _ := c.Cookie("oauth_state")
	if state == "" || state != c.Query("state") {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=invalid_state", h.cfg.FrontendURL))
		return
	}

	code := c.Query("code")
	if code == "" {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=no_code", h.cfg.FrontendURL))
		return
	}

	cfg := h.nodelocOAuthConfig()

	token, err := cfg.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("NodeLoc OAuth exchange error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=exchange_failed", h.cfg.FrontendURL))
		return
	}

	nodelocUser, err := h.fetchNodelocUser(token.AccessToken)
	if err != nil {
		fmt.Printf("NodeLoc fetch user error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=fetch_user_failed", h.cfg.FrontendURL))
		return
	}

	if nodelocUser.Email == "" {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=no_email", h.cfg.FrontendURL))
		return
	}

	username := nodelocUser.PreferredUsername
	if username == "" {
		username = strings.Split(nodelocUser.Email, "@")[0]
	}

	// 根据 trust_level 确定用户等级和配额
	userLevel := TrustLevelToUserLevel(nodelocUser.TrustLevel)
	quota := GetQuotaForLevel(h.db, userLevel)

	user, err := h.findOrCreateOAuthUser("nodeloc", nodelocUser.Sub, nodelocUser.Email, username, nodelocUser.Picture, c.ClientIP(), userLevel, quota)
	if err != nil {
		fmt.Printf("OAuth find/create user error: %v\n", err)
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=%s", h.cfg.FrontendURL, url.QueryEscape("create_user_failed: "+err.Error())))
		return
	}

	jwtToken, err := generateToken(user, h.cfg)
	if err != nil {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?error=token_failed", h.cfg.FrontendURL))
		return
	}

	c.Redirect(http.StatusFound, fmt.Sprintf("%s/auth/callback?token=%s", h.cfg.FrontendURL, jwtToken))
}

// NodeLoc API types
type nodelocUser struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Picture           string `json:"picture"`
	TrustLevel        int    `json:"trust_level"`
}

func (h *OAuthHandler) fetchNodelocUser(accessToken string) (*nodelocUser, error) {
	req, _ := http.NewRequest("GET", "https://www.nodeloc.com/oauth-provider/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var user nodelocUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}
	return &user, nil
}
