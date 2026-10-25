package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"opendomain/internal/config"
	"opendomain/internal/middleware"
	"opendomain/internal/models"
	"opendomain/pkg/powerdns"
	"opendomain/pkg/timeutil"
)

// PaymentHandler 支付处理器
type PaymentHandler struct {
	db   *gorm.DB
	cfg  *config.Config
	pdns *powerdns.Client
}

// NewPaymentHandler 创建支付处理器
func NewPaymentHandler(db *gorm.DB, cfg *config.Config) *PaymentHandler {
	return &PaymentHandler{
		db:   db,
		cfg:  cfg,
		pdns: powerdns.NewClient(cfg.PowerDNS.APIURL, cfg.PowerDNS.APIKey),
	}
}

// InitiatePayment 发起支付
func (h *PaymentHandler) InitiatePayment(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	orderID := c.Param("orderId")

	// 获取订单
	var order models.Order
	if err := h.db.Where("id = ? AND user_id = ?", orderID, userID).First(&order).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Order not found"})
		return
	}

	// 检查订单状态
	if order.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Order is not pending"})
		return
	}

	// 检查订单是否过期
	if timeutil.Now().After(order.ExpiresAt) {
		order.Status = "expired"
		h.db.Save(&order)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Order has expired"})
		return
	}

	// 检查订单金额是否有效（必须 > 0.01）
	if order.FinalPrice < 0.01 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Order amount is too small for payment. Please use complete-free endpoint for orders under 0.01",
		})
		return
	}

	// 检查是否已有支付记录
	var existingPayment models.Payment
	if err := h.db.Where("order_id = ? AND status IN (?)", order.ID, []string{"pending", "processing", "completed"}).First(&existingPayment).Error; err == nil {
		// 如果已完成，返回错误
		if existingPayment.Status == "completed" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Order already paid"})
			return
		}
		// 如果是 pending 或 processing，重新发起支付
		redirectURL, err := h.initiateNodelocPayment(&existingPayment, &order)
		if err != nil {
			fmt.Printf("Failed to re-initiate NodeLoc payment: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to initiate payment: %v", err)})
			return
		}
		c.JSON(http.StatusOK, models.PaymentInitiateResponse{
			PaymentID:   existingPayment.ID,
			RedirectURL: redirectURL,
		})
		return
	}

	// 创建支付记录
	payment := &models.Payment{
		OrderID:          order.ID,
		NodelocPaymentID: h.cfg.Payment.NodelocPaymentID,
		Amount:           order.FinalPrice,
		Currency:         "CNY",
		Status:           "pending",
	}

	if err := h.db.Create(payment).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create payment"})
		return
	}

	// 调用 NodeLoc API 发起支付
	redirectURL, err := h.initiateNodelocPayment(payment, &order)
	if err != nil {
		fmt.Printf("Failed to initiate NodeLoc payment: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to initiate payment: %v", err)})
		return
	}

	c.JSON(http.StatusOK, models.PaymentInitiateResponse{
		PaymentID:   payment.ID,
		RedirectURL: redirectURL,
	})
}

// HandleReturn 处理用户从支付页面返回
func (h *PaymentHandler) HandleReturn(c *gin.Context) {
	orderNumber := c.Query("order_id")
	if orderNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing order_id"})
		return
	}

	// 查找订单
	var order models.Order
	if err := h.db.Where("order_number = ?", orderNumber).First(&order).Error; err != nil {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/payment/failure?message=Order+not+found", h.cfg.FrontendURL))
		return
	}

	// 查找支付记录
	var payment models.Payment
	if err := h.db.Where("order_id = ?", order.ID).First(&payment).Error; err != nil {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/payment/failure?order_id=%d", h.cfg.FrontendURL, order.ID))
		return
	}

	// 根据支付状态重定向
	if payment.Status == "completed" {
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/payment/success?order_id=%d", h.cfg.FrontendURL, order.ID))
	} else {
		// 支付可能还在处理中，让用户等待回调
		c.Redirect(http.StatusFound, fmt.Sprintf("%s/payment/processing?order_id=%d", h.cfg.FrontendURL, order.ID))
	}
}

// CompleteFreeOrder 完成免费订单（价格为0时使用）
func (h *PaymentHandler) CompleteFreeOrder(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	orderID := c.Param("orderId")

	// 查找订单
	var order models.Order
	if err := h.db.Preload("RootDomain").Where("id = ? AND user_id = ?", orderID, userID).First(&order).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Order not found"})
		return
	}

	// 验证订单价格为0
	if order.FinalPrice != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This order requires payment"})
		return
	}

	// 验证订单状态
	if order.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Order already processed"})
		return
	}

	// 开始事务
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 标记订单为已支付
	now := timeutil.Now()
	order.Status = "paid"
	order.PaidAt = &now
	if err := tx.Save(&order).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update order status"})
		return
	}

	// 创建域名
	if err := h.createDomainFromOrder(tx, &order); err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create domain"})
		return
	}

	tx.Commit()

	// 在 PowerDNS 中创建/更新 child zone 与父区委派
	if order.DomainID != nil {
		var domain models.Domain
		if err := h.db.Preload("RootDomain").First(&domain, *order.DomainID).Error; err == nil {
			if domain.RootDomain != nil {
				var nameservers []string
				if err := json.Unmarshal([]byte(domain.Nameservers), &nameservers); err == nil {
					go h.updateDomainNSRecordsInPowerDNS(&domain, nameservers, domain.UseDefaultNameservers)
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Free order completed successfully",
		"order_id": order.ID,
	})
}

// HandleCallback 处理支付回调
func (h *PaymentHandler) HandleCallback(c *gin.Context) {
	// 先获取原始查询参数用于签名验证
	rawParams := make(map[string]string)
	for key, values := range c.Request.URL.Query() {
		if len(values) > 0 && key != "signature" {
			rawParams[key] = values[0]
		}
	}
	signature := c.Query("signature")

	var req models.NodelocCallbackRequest
	if err := c.ShouldBind(&req); err != nil {
		fmt.Printf("Callback binding error: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid callback data"})
		return
	}

	// 记录回调信息
	fmt.Printf("Received payment callback: transaction_id=%s, status=%s, amount=%.2f\n",
		req.TransactionID, req.Status, req.Amount)

	// 验证签名（使用原始参数）
	if !h.verifyCallbackSignature(rawParams, signature) {
		fmt.Printf("Invalid signature for transaction: %s\n", req.TransactionID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
		return
	}

	// 查找订单
	var order models.Order
	if err := h.db.Where("order_number = ?", req.ExternalReference).First(&order).Error; err != nil {
		fmt.Printf("Order not found: %s\n", req.ExternalReference)
		c.JSON(http.StatusNotFound, gin.H{"error": "Order not found"})
		return
	}

	// 查找支付记录
	var payment models.Payment
	if err := h.db.Where("order_id = ?", order.ID).First(&payment).Error; err != nil {
		fmt.Printf("Payment record not found for order: %s\n", order.OrderNumber)
		c.JSON(http.StatusNotFound, gin.H{"error": "Payment not found"})
		return
	}

	// 检查是否已处理（幂等性）
	if payment.TransactionID != nil && *payment.TransactionID == req.TransactionID {
		if payment.Status == "completed" {
			fmt.Printf("Payment already processed: %s\n", req.TransactionID)
			c.Redirect(http.StatusFound, h.getSuccessRedirectURL(&order))
			return
		}
	}

	// 验证金额
	if req.Amount != order.FinalPrice {
		fmt.Printf("Amount mismatch: expected %.2f, got %.2f\n", order.FinalPrice, req.Amount)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Amount mismatch"})
		return
	}

	// 根据支付状态处理
	now := timeutil.Now()
	clientIP := c.ClientIP()

	if req.Status == "completed" {
		// 开始事务处理
		if err := h.processSuccessfulPayment(&payment, &order, &req, now, clientIP); err != nil {
			fmt.Printf("Failed to process payment: %v\n", err)
			errMsg := fmt.Sprintf("Failed to process payment: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": errMsg})
			return
		}

		// 在 PowerDNS 中创建/更新 child zone 与父区委派
		if order.DomainID != nil {
			var domain models.Domain
			if err := h.db.Preload("RootDomain").First(&domain, *order.DomainID).Error; err == nil {
				if domain.RootDomain != nil {
					var nameservers []string
					if err := json.Unmarshal([]byte(domain.Nameservers), &nameservers); err == nil {
						go h.updateDomainNSRecordsInPowerDNS(&domain, nameservers, domain.UseDefaultNameservers)
					}
				}
			}
		}

		fmt.Printf("Payment processed successfully: %s\n", req.TransactionID)
		c.Redirect(http.StatusFound, h.getSuccessRedirectURL(&order))
	} else {
		// 支付失败或取消
		payment.TransactionID = &req.TransactionID
		payment.Status = "failed"
		payment.CallbackReceivedAt = &now
		payment.CallbackIP = &clientIP

		gatewayResponse := fmt.Sprintf("status=%s", req.Status)
		payment.GatewayResponse = &gatewayResponse
		payment.Signature = &req.Signature

		h.db.Save(&payment)

		order.Status = "cancelled"
		h.db.Save(&order)

		fmt.Printf("Payment failed: %s, status=%s\n", req.TransactionID, req.Status)
		c.Redirect(http.StatusFound, h.getFailureRedirectURL(&order))
	}
}

// QueryPaymentStatus 查询支付状态
func (h *PaymentHandler) QueryPaymentStatus(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	orderID := c.Param("orderId")

	// 获取订单
	var order models.Order
	if err := h.db.Where("id = ? AND user_id = ?", orderID, userID).First(&order).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Order not found"})
		return
	}

	// 获取支付记录
	var payment models.Payment
	if err := h.db.Where("order_id = ?", order.ID).First(&payment).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Payment not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"payment_id":           payment.ID,
		"order_id":             order.ID,
		"order_number":         order.OrderNumber,
		"amount":               payment.Amount,
		"currency":             payment.Currency,
		"status":               payment.Status,
		"transaction_id":       payment.TransactionID,
		"created_at":           payment.CreatedAt,
		"callback_received_at": payment.CallbackReceivedAt,
		"completed_at":         payment.CompletedAt,
	})
}

// processSuccessfulPayment 处理成功的支付（事务）
func (h *PaymentHandler) processSuccessfulPayment(
	payment *models.Payment,
	order *models.Order,
	req *models.NodelocCallbackRequest,
	now time.Time,
	clientIP string,
) error {
	return h.db.Transaction(func(tx *gorm.DB) error {
		// 锁定订单行
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", order.ID).First(order).Error; err != nil {
			return err
		}

		// 再次检查订单状态
		if order.Status == "paid" {
			return fmt.Errorf("order already paid")
		}

		// 更新支付记录
		payment.TransactionID = &req.TransactionID
		payment.Status = "completed"
		payment.CallbackReceivedAt = &now
		payment.CompletedAt = &now
		payment.CallbackIP = &clientIP

		gatewayResponse := fmt.Sprintf("status=%s,amount=%.2f,paid_at=%s",
			req.Status, req.Amount, req.PaidAt)
		payment.GatewayResponse = &gatewayResponse
		payment.Signature = &req.Signature

		if err := tx.Save(payment).Error; err != nil {
			return err
		}

		// 检查是否为续费订单（如果 order.DomainID 已存在，表示续费）
		if order.DomainID != nil && *order.DomainID > 0 {
			// 续费：更新现有域名的过期时间
			var domain models.Domain
			if err := tx.First(&domain, *order.DomainID).Error; err != nil {
				return fmt.Errorf("failed to find domain for renewal: %w", err)
			}

			// 计算新的过期时间（从当前过期时间延长）
			maxExpiry := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
			var newExpiresAt time.Time
			if order.IsLifetime {
				// 永久域名设置为100年后
				newExpiresAt = domain.ExpiresAt.AddDate(100, 0, 0)
			} else {
				newExpiresAt = domain.ExpiresAt.AddDate(order.Years, 0, 0)
			}
			if newExpiresAt.After(maxExpiry) {
				newExpiresAt = maxExpiry
			}

			// 更新域名过期时间
			if err := tx.Model(&domain).Update("expires_at", newExpiresAt).Error; err != nil {
				return fmt.Errorf("failed to update domain expiry: %w", err)
			}

			// 更新订单状态
			order.Status = "paid"
			order.PaidAt = &now

			if err := tx.Save(order).Error; err != nil {
				return err
			}

			// 记录优惠券使用（如果有）
			if order.CouponID != nil {
				usage := &models.CouponUsage{
					CouponID: *order.CouponID,
					UserID:   order.UserID,
					DomainID: order.DomainID,
				}
				if err := tx.Create(usage).Error; err != nil {
					return err
				}

				// 更新优惠券使用次数
				if err := tx.Model(&models.Coupon{}).
					Where("id = ?", order.CouponID).
					UpdateColumn("used_count", gorm.Expr("used_count + ?", 1)).Error; err != nil {
					return err
				}
			}

			fmt.Printf("Domain %s renewed successfully, new expiry: %s\n", domain.FullDomain, newExpiresAt)
		} else {
			// 新注册：创建新域名
			var expiresAt time.Time
			if order.IsLifetime {
				// 永久域名设置为100年后
				expiresAt = now.AddDate(100, 0, 0)
			} else {
				expiresAt = now.AddDate(order.Years, 0, 0)
			}

			// 获取根域名的 NS 设置
			var rd models.RootDomain
			if err := tx.First(&rd, order.RootDomainID).Error; err != nil {
				return fmt.Errorf("root domain not found: %w", err)
			}

			// 检查是否存在软删除记录（unique constraint 依然生效，需要恢复而非新建）
			var softDeleted models.Domain
			hasSoftDeleted := tx.Unscoped().Where("full_domain = ? AND deleted_at IS NOT NULL", order.FullDomain).First(&softDeleted).Error == nil

			var domain *models.Domain
			if hasSoftDeleted {
				// 恢复软删除记录并重新分配
				updates := map[string]interface{}{
					"user_id":                 order.UserID,
					"root_domain_id":          order.RootDomainID,
					"subdomain":               order.Subdomain,
					"status":                  "active",
					"registered_at":           now,
					"expires_at":              expiresAt,
					"auto_renew":              false,
					"nameservers":             rd.Nameservers,
					"use_default_nameservers": rd.UseDefaultNameservers,
					"dns_synced":              false,
					"dns_sync_error":          nil,
					"first_failed_at":         nil,
					"suspended_at":            nil,
					"suspend_reason":          nil,
					"deleted_at":              nil,
				}
				if err := tx.Unscoped().Model(&softDeleted).Updates(updates).Error; err != nil {
					return fmt.Errorf("failed to restore domain %s: %w", order.FullDomain, err)
				}
				domain = &softDeleted
			} else {
				// 创建新域名记录
				domain = &models.Domain{
					UserID:                order.UserID,
					RootDomainID:          order.RootDomainID,
					Subdomain:             order.Subdomain,
					FullDomain:            order.FullDomain,
					Status:                "active",
					RegisteredAt:          now,
					ExpiresAt:             expiresAt,
					AutoRenew:             false,
					Nameservers:           rd.Nameservers,
					UseDefaultNameservers: rd.UseDefaultNameservers,
					DNSSynced:             false,
				}
				if err := tx.Create(domain).Error; err != nil {
					return fmt.Errorf("failed to create domain %s: %w", order.FullDomain, err)
				}
			}

			// 更新订单
			order.Status = "paid"
			order.PaidAt = &now
			order.DomainID = &domain.ID

			if err := tx.Save(order).Error; err != nil {
				return err
			}

			// 记录优惠券使用（新注册）
			if order.CouponID != nil {
				usage := &models.CouponUsage{
					CouponID: *order.CouponID,
					UserID:   order.UserID,
					DomainID: &domain.ID,
				}
				if err := tx.Create(usage).Error; err != nil {
					return err
				}

				// 更新优惠券使用次数
				if err := tx.Model(&models.Coupon{}).
					Where("id = ?", order.CouponID).
					UpdateColumn("used_count", gorm.Expr("used_count + ?", 1)).Error; err != nil {
					return err
				}
			}

			// 更新根域名注册数量（仅新注册）
			if err := tx.Model(&models.RootDomain{}).
				Where("id = ?", order.RootDomainID).
				UpdateColumn("registration_count", gorm.Expr("registration_count + ?", 1)).Error; err != nil {
				return err
			}

			fmt.Printf("Domain %s created successfully, expiry: %s\n", domain.FullDomain, expiresAt)
		}

		return nil
	})
}

// initiateNodelocPayment 调用 NodeLoc API 发起支付
func (h *PaymentHandler) initiateNodelocPayment(payment *models.Payment, order *models.Order) (string, error) {
	// NodeLoc 使用积分系统，1 积分 = 1 元，所以直接使用金额作为整数
	amount := int(payment.Amount)

	// NodeLoc 支付参数（只有这些参数参与签名计算）
	params := map[string]string{
		"amount":      fmt.Sprintf("%d", amount),
		"description": fmt.Sprintf("Domain: %s", order.Subdomain),
		"order_id":    order.OrderNumber,
	}

	// 生成签名（使用原始未编码的值）
	signature := h.generateSignature(params)

	// 调试日志
	fmt.Printf("[DEBUG] Payment initiation:\n")
	fmt.Printf("  Amount: %s\n", params["amount"])
	fmt.Printf("  Description: %s\n", params["description"])
	fmt.Printf("  Order ID: %s\n", params["order_id"])
	fmt.Printf("  Signature: %s\n", signature)
	fmt.Printf("  Payment ID: %s\n", h.cfg.Payment.NodelocPaymentID)

	// 构建请求 URL
	apiURL := fmt.Sprintf("https://www.nodeloc.com/payment/pay/%s/process", h.cfg.Payment.NodelocPaymentID)
	if h.cfg.Payment.IsTestMode {
		apiURL = fmt.Sprintf("https://test.nodeloc.com/payment/pay/%s/process", h.cfg.Payment.NodelocPaymentID)
	}

	// 构建表单数据（与官方 SDK 一致）
	formData := make(map[string][]string)
	formData["amount"] = []string{params["amount"]}
	formData["description"] = []string{params["description"]}
	formData["order_id"] = []string{params["order_id"]}
	formData["signature"] = []string{signature}

	fmt.Printf("  Form data: %v\n", formData)

	// 发起 POST 请求（使用表单编码）
	resp, err := http.PostForm(apiURL, formData)
	if err != nil {
		return "", fmt.Errorf("failed to call NodeLoc API: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// 记录完整响应用于调试
	fmt.Printf("[DEBUG] NodeLoc API Response:\n")
	fmt.Printf("  Status Code: %d\n", resp.StatusCode)
	fmt.Printf("  Response Body: %s\n", string(body))

	// 检查状态码
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("NodeLoc API returned status %d: %s", resp.StatusCode, string(body))
	}

	// 解析响应 - NodeLoc 直接返回支付信息，不是嵌套结构
	var result struct {
		PaymentURL    string  `json:"payment_url"`
		TransactionID string  `json:"transaction_id"`
		Status        string  `json:"status"`
		Amount        float64 `json:"amount"`
		Error         string  `json:"error,omitempty"` // 如果有错误
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response (body: %s): %w", string(body), err)
	}

	// 检查是否有错误
	if result.Error != "" {
		return "", fmt.Errorf("NodeLoc API error: %s", result.Error)
	}

	if result.PaymentURL == "" {
		return "", fmt.Errorf("no payment URL in response (full response: %s)", string(body))
	}

	// 更新支付记录的 transaction_id
	payment.TransactionID = &result.TransactionID
	if err := h.db.Save(payment).Error; err != nil {
		fmt.Printf("Warning: failed to update payment transaction_id: %v\n", err)
	}

	fmt.Printf("  Payment URL: %s\n", result.PaymentURL)
	fmt.Printf("  Transaction ID: %s\n", result.TransactionID)
	return result.PaymentURL, nil
}

// generateSignature 生成签名
func (h *PaymentHandler) generateSignature(params map[string]string) string {
	// 1. 按字母顺序排序参数
	var keys []string
	for k := range params {
		if k != "signature" { // 排除签名字段本身
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	// 2. 构建签名字符串
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, params[k]))
	}
	message := strings.Join(parts, "&")

	// 调试日志
	fmt.Printf("[DEBUG] Signature generation:\n")
	fmt.Printf("  Message string: %s\n", message)

	// 修剪密钥以去除可能的空白字符
	secretKey := strings.TrimSpace(h.cfg.Payment.NodelocSecretKey)
	fmt.Printf("  Secret key (first 10 chars): %s...\n", secretKey[:10])
	fmt.Printf("  Secret key length: %d\n", len(secretKey))

	// 3. 计算 token_hash = SHA256(secret_key) 并转换为十六进制字符串
	tokenHash := sha256.Sum256([]byte(secretKey))
	tokenHashHex := hex.EncodeToString(tokenHash[:])
	fmt.Printf("  Token hash (hex): %s\n", tokenHashHex)

	// 4. 使用十六进制字符串作为 HMAC 密钥（这是关键！）
	mac := hmac.New(sha256.New, []byte(tokenHashHex))
	mac.Write([]byte(message))
	signature := hex.EncodeToString(mac.Sum(nil))

	fmt.Printf("  Generated signature: %s\n", signature)

	return signature
}

// generateSignatureFromString 从字符串生成签名（用于已编码的参数字符串）
func (h *PaymentHandler) generateSignatureFromString(message string) string {
	// 修剪密钥以去除可能的空白字符
	secretKey := strings.TrimSpace(h.cfg.Payment.NodelocSecretKey)

	// 计算 token_hash = SHA256(secret_key) 并转换为十六进制字符串
	tokenHash := sha256.Sum256([]byte(secretKey))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	// 使用十六进制字符串作为 HMAC 密钥
	mac := hmac.New(sha256.New, []byte(tokenHashHex))
	mac.Write([]byte(message))
	signature := hex.EncodeToString(mac.Sum(nil))

	return signature
}

// verifyCallbackSignature 验证回调签名（使用原始参数值）
// 注意：回调验证直接使用 secret_key，不需要 SHA256 哈希
func (h *PaymentHandler) verifyCallbackSignature(rawParams map[string]string, signature string) bool {
	// 1. 按字母顺序排序参数
	var keys []string
	for k := range rawParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 2. 构建签名字符串
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, rawParams[k]))
	}
	message := strings.Join(parts, "&")

	// 调试日志
	fmt.Printf("[DEBUG] Callback signature verification:\n")
	fmt.Printf("  Received signature: %s\n", signature)
	fmt.Printf("  Parameters: %+v\n", rawParams)
	fmt.Printf("  Sorted keys: %v\n", keys)
	fmt.Printf("  Message string: %s\n", message)

	// 3. 使用和发起支付相同的算法：先对 secret_key 进行 SHA256 哈希，转成十六进制
	secretKey := strings.TrimSpace(h.cfg.Payment.NodelocSecretKey)
	fmt.Printf("  Secret key (first 10 chars): %s...\n", secretKey[:10])

	// 计算 token_hash = SHA256(secret_key) 并转换为十六进制字符串
	tokenHash := sha256.Sum256([]byte(secretKey))
	tokenHashHex := hex.EncodeToString(tokenHash[:])
	fmt.Printf("  Token hash (hex): %s\n", tokenHashHex)

	// 使用十六进制字符串作为 HMAC 密钥
	mac := hmac.New(sha256.New, []byte(tokenHashHex))
	mac.Write([]byte(message))
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	fmt.Printf("  Expected signature: %s\n", expectedSignature)
	fmt.Printf("  Signatures match: %v\n", expectedSignature == signature)

	// 使用恒定时间比较防止时序攻击
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

// getSuccessRedirectURL 获取成功重定向URL
func (h *PaymentHandler) getSuccessRedirectURL(order *models.Order) string {
	return fmt.Sprintf("%s/payment/success?order_id=%d", h.cfg.FrontendURL, order.ID)
}

// getFailureRedirectURL 获取失败重定向URL
func (h *PaymentHandler) getFailureRedirectURL(order *models.Order) string {
	return fmt.Sprintf("%s/payment/failure?order_id=%d", h.cfg.FrontendURL, order.ID)
}

// createDomainFromOrder 从订单创建域名（用于免费订单和支付成功后）
func (h *PaymentHandler) createDomainFromOrder(tx *gorm.DB, order *models.Order) error {
	now := timeutil.Now()

	// 检查是否为续费订单（如果 order.DomainID 已存在，表示续费）
	if order.DomainID != nil && *order.DomainID > 0 {
		// 续费：更新现有域名的过期时间
		var domain models.Domain
		if err := tx.First(&domain, *order.DomainID).Error; err != nil {
			return fmt.Errorf("failed to find domain for renewal: %w", err)
		}

		// 计算新的过期时间（从当前过期时间延长）
		maxExpiry := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		var newExpiresAt time.Time
		if order.IsLifetime {
			// 永久域名设置为100年后
			newExpiresAt = domain.ExpiresAt.AddDate(100, 0, 0)
		} else {
			newExpiresAt = domain.ExpiresAt.AddDate(order.Years, 0, 0)
		}
		if newExpiresAt.After(maxExpiry) {
			newExpiresAt = maxExpiry
		}

		// 更新域名过期时间
		if err := tx.Model(&domain).Update("expires_at", newExpiresAt).Error; err != nil {
			return fmt.Errorf("failed to update domain expiry: %w", err)
		}

		// 更新订单状态
		order.Status = "paid"
		order.PaidAt = &now

		if err := tx.Save(order).Error; err != nil {
			return err
		}

		// 记录优惠券使用（如果有）
		if order.CouponID != nil {
			usage := &models.CouponUsage{
				CouponID: *order.CouponID,
				UserID:   order.UserID,
				DomainID: order.DomainID,
			}
			if err := tx.Create(usage).Error; err != nil {
				return err
			}

			// 更新优惠券使用次数
			if err := tx.Model(&models.Coupon{}).
				Where("id = ?", order.CouponID).
				UpdateColumn("used_count", gorm.Expr("used_count + ?", 1)).Error; err != nil {
				return err
			}
		}

		fmt.Printf("Domain %s renewed successfully (free), new expiry: %s\n", domain.FullDomain, newExpiresAt)
		return nil
	}

	// 新注册：创建新域名
	var expiresAt time.Time
	if order.IsLifetime {
		// 永久域名设置为100年后
		expiresAt = now.AddDate(100, 0, 0)
	} else {
		expiresAt = now.AddDate(order.Years, 0, 0)
	}

	// 获取根域名的 NS 设置
	var rootDomainNS string
	var rootDomainUseDefault bool
	if order.RootDomain != nil {
		rootDomainNS = order.RootDomain.Nameservers
		rootDomainUseDefault = order.RootDomain.UseDefaultNameservers
	} else {
		var rd models.RootDomain
		if err := tx.First(&rd, order.RootDomainID).Error; err == nil {
			rootDomainNS = rd.Nameservers
			rootDomainUseDefault = rd.UseDefaultNameservers
		}
	}

	// 创建域名
	domain := &models.Domain{
		UserID:                order.UserID,
		RootDomainID:          order.RootDomainID,
		Subdomain:             order.Subdomain,
		FullDomain:            order.FullDomain,
		Status:                "active",
		RegisteredAt:          now,
		ExpiresAt:             expiresAt,
		AutoRenew:             false,
		Nameservers:           rootDomainNS,
		UseDefaultNameservers: rootDomainUseDefault,
		DNSSynced:             false,
	}

	// 先检查是否存在软删除记录，存在则直接恢复（partial index 已保证软删除记录不占唯一约束）
	var softDeleted models.Domain
	if dbErr := tx.Unscoped().Where("full_domain = ? AND deleted_at IS NOT NULL", domain.FullDomain).First(&softDeleted).Error; dbErr == nil {
		// 恢复软删除记录，同时清除历史挂起/失败状态，避免 scanner 误判
		if restoreErr := tx.Unscoped().Model(&softDeleted).Updates(map[string]interface{}{
			"deleted_at":              nil,
			"user_id":                 domain.UserID,
			"status":                  domain.Status,
			"expires_at":              domain.ExpiresAt,
			"registered_at":           domain.RegisteredAt,
			"auto_renew":              domain.AutoRenew,
			"nameservers":             domain.Nameservers,
			"use_default_nameservers": domain.UseDefaultNameservers,
			"dns_synced":              false,
			"dns_sync_error":          nil,
			// 清除历史挂起/失败记录，防止 scanner 按旧时间戳触发自动删除
			"first_failed_at": nil,
			"suspended_at":    nil,
			"suspend_reason":  nil,
		}).Error; restoreErr != nil {
			return fmt.Errorf("failed to restore domain %s: %w", domain.FullDomain, restoreErr)
		}
		domain.ID = softDeleted.ID
	} else {
		// 不存在软删除记录，正常创建
		if err := tx.Create(domain).Error; err != nil {
			return fmt.Errorf("failed to create domain %s: %w", domain.FullDomain, err)
		}
	}

	// 更新订单
	order.Status = "paid"
	order.PaidAt = &now
	order.DomainID = &domain.ID

	if err := tx.Save(order).Error; err != nil {
		return err
	}

	// 记录优惠券使用
	if order.CouponID != nil {
		// 检查是否已存在使用记录（避免重复记录）
		var existingUsage models.CouponUsage
		err := tx.Where("coupon_id = ? AND user_id = ?", order.CouponID, order.UserID).First(&existingUsage).Error

		// 如果不存在，则创建新记录
		if err == gorm.ErrRecordNotFound {
			usage := &models.CouponUsage{
				CouponID: *order.CouponID,
				UserID:   order.UserID,
				DomainID: &domain.ID,
			}
			if err := tx.Create(usage).Error; err != nil {
				return err
			}

			// 更新优惠券使用次数
			if err := tx.Model(&models.Coupon{}).
				Where("id = ?", order.CouponID).
				UpdateColumn("used_count", gorm.Expr("used_count + ?", 1)).Error; err != nil {
				return err
			}
		} else if err != nil {
			// 其他错误
			return err
		}
		// 如果已存在记录，则跳过插入（表示用户之前已经使用过这张优惠券）
	}

	// 更新根域名注册数量
	if err := tx.Model(&models.RootDomain{}).
		Where("id = ?", order.RootDomainID).
		UpdateColumn("registration_count", gorm.Expr("registration_count + ?", 1)).Error; err != nil {
		return err
	}

	return nil
}

// updateDomainNSRecordsInPowerDNS 更新域名在 PowerDNS root zone 中的 NS 记录
// 默认和自定义 nameservers 都必须同步到 root domain 的 NS 委派。
func (h *PaymentHandler) updateDomainNSRecordsInPowerDNS(domain *models.Domain, nameservers []string, isDefault bool) {
	if domain.RootDomain == nil {
		fmt.Printf("Warning: Cannot update NS records for domain %s: root domain not loaded\n", domain.FullDomain)
		return
	}

	rootDomain := domain.RootDomain.Domain
	subdomainFQDN := domain.FullDomain

	// 默认 NS 使用独立 child zone；PowerDNS 不会自动创建父区委派。
	if isDefault {
		if err := dropForeignDS(h.pdns, rootDomain, subdomainFQDN); err != nil {
			fmt.Printf("Warning: Failed to remove custom-NS DS records for %s: %v\n", subdomainFQDN, err)
			return
		}
		defaultNS := ensureCanonicalNS([]string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2})
		if err := h.pdns.EnsureDelegatedZone(subdomainFQDN, rootDomain, defaultNS); err != nil {
			fmt.Printf("Warning: Failed to create delegated zone for %s in PowerDNS: %v\n", subdomainFQDN, err)
			return
		}
		fmt.Printf("Ensured delegated zone for %s with default nameservers: %v\n", subdomainFQDN, defaultNS)
		return
	}

	// 自定义 NS 不应继续保留本地 child zone 的 DS 或区域数据。
	if err := dropLocalDS(h.pdns, rootDomain, subdomainFQDN); err != nil {
		fmt.Printf("Warning: Failed to remove old DS records for %s: %v\n", subdomainFQDN, err)
		return
	}
	if err := h.pdns.DeleteZone(subdomainFQDN); err != nil &&
		!strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "Could not find") {
		fmt.Printf("Warning: Failed to delete local zone for %s: %v\n", subdomainFQDN, err)
		return
	}

	if err := h.pdns.SetDelegation(rootDomain, subdomainFQDN, ensureCanonicalNS(nameservers)); err != nil {
		fmt.Printf("Warning: Failed to set NS records for %s in PowerDNS: %v\n", subdomainFQDN, err)
	} else {
		fmt.Printf("Updated NS records for %s with custom nameservers: %v\n", subdomainFQDN, nameservers)
	}
}
