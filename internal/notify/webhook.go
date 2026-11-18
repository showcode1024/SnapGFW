package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"natgfw/internal/model"
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

func (n *Notifier) loop() {
	for {
		select {
		case <-n.stopCh:
			return
		case task := <-n.queue:
			n.dispatch(task)
		}
	}
}

func (n *Notifier) dispatch(t notifyTask) {
	if t.cfg.WebhookURL != "" {
		body, err := json.Marshal(map[string]any{
			"title":   t.title,
			"message": t.message,
			"data":    t.payload,
			"ts":      time.Now().UTC().Format(time.RFC3339),
		})
		if err == nil {
			req, err := http.NewRequest(http.MethodPost, t.cfg.WebhookURL, bytes.NewReader(body))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				if resp, err := n.client.Do(req); err == nil {
					_ = resp.Body.Close()
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
		if resp, err := n.client.PostForm(apiURL, form); err == nil {
			_ = resp.Body.Close()
		}
	}
}
