package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"snapgfw/internal/model"
)

// Notifier dispatches rate-limited asynchronous alerts to Telegram and/or generic Webhooks.
type Notifier struct {
	client   *http.Client
	mu       sync.Mutex
	lastSent map[string]time.Time
	queue    chan notifyTask
	stopCh   chan struct{}
}

type notifyTask struct {
	cfg     model.NotifyConfig
	title   string
	message string
	payload any
}

// NewNotifier creates and starts a background async notifier.
func NewNotifier() *Notifier {
	n := &Notifier{
		client:   &http.Client{Timeout: 8 * time.Second},
		lastSent: make(map[string]time.Time),
		queue:    make(chan notifyTask, 64),
		stopCh:   make(chan struct{}),
	}
	go n.loop()
	return n
}

// Close drains/stops the background notifier.
func (n *Notifier) Close() {
	close(n.stopCh)
}

// Send queues an alert respecting per-key cooldown; drops cleanly if queue is full.
func (n *Notifier) Send(cfg model.NotifyConfig, key, title, message string, payload any) {
	if cfg.WebhookURL == "" && (cfg.TelegramToken == "" || cfg.TelegramChatID == "") {
		return
	}
	cooldown := time.Duration(max(cfg.MinIntervalSec, 15)) * time.Second
	now := time.Now()

	n.mu.Lock()
	if prev, ok := n.lastSent[key]; ok && now.Sub(prev) < cooldown {
		n.mu.Unlock()
		return
	}
	n.lastSent[key] = now
	if len(n.lastSent) > 4096 {
		for k, t := range n.lastSent {
			if now.Sub(t) > cooldown*2 {
				delete(n.lastSent, k)
			}
		}
	}
	n.mu.Unlock()

	select {
	case n.queue <- notifyTask{cfg: cfg, title: title, message: message, payload: payload}:
	default:
	}
}

// SendSync immediately dispatches an alert and returns any delivery/HTTP error (used for test button).
func (n *Notifier) SendSync(cfg model.NotifyConfig, title, message string, payload any) error {
	if cfg.WebhookURL == "" && (cfg.TelegramToken == "" || cfg.TelegramChatID == "") {
		return errors.New("未配置 Webhook URL 或 Telegram")
	}
	return n.dispatch(notifyTask{cfg: cfg, title: title, message: message, payload: payload})
}

func (n *Notifier) loop() {
	for {
		select {
		case <-n.stopCh:
			return
		case task := <-n.queue:
			_ = n.dispatch(task)
		}
	}
}

func (n *Notifier) dispatch(t notifyTask) error {
	var errs []string
	if t.cfg.WebhookURL != "" {
		body, err := json.Marshal(map[string]any{
			"title":   t.title,
			"message": t.message,
			"data":    t.payload,
			"ts":      time.Now().UTC().Format(time.RFC3339),
		})
		if err != nil {
			errs = append(errs, "webhook marshal: "+err.Error())
		} else {
			req, err := http.NewRequest(http.MethodPost, t.cfg.WebhookURL, bytes.NewReader(body))
			if err != nil {
				errs = append(errs, "webhook url: "+err.Error())
			} else {
				req.Header.Set("Content-Type", "application/json")
				resp, err := n.client.Do(req)
				if err != nil {
					errs = append(errs, "webhook: "+err.Error())
				} else {
					snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
					_ = resp.Body.Close()
					if resp.StatusCode >= 300 {
						errs = append(errs, fmt.Sprintf("webhook HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet))))
					}
				}
			}
		}
	}

	if t.cfg.TelegramToken != "" && t.cfg.TelegramChatID != "" {
		apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", url.PathEscape(t.cfg.TelegramToken))
		form := url.Values{
			"chat_id": {t.cfg.TelegramChatID},
			"text":    {fmt.Sprintf("[%s]\n%s", t.title, t.message)},
		}
		resp, err := n.client.PostForm(apiURL, form)
		if err != nil {
			errs = append(errs, "telegram: "+err.Error())
		} else {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			_ = resp.Body.Close()
			if resp.StatusCode >= 300 {
				errs = append(errs, fmt.Sprintf("telegram HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet))))
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
