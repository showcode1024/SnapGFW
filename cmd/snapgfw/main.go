package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"snapgfw/internal/config"
	"snapgfw/internal/engine"
	"snapgfw/internal/model"
	"snapgfw/internal/netfilter"
	"snapgfw/internal/notify"
	"snapgfw/internal/runman"
	"snapgfw/internal/store"
	"snapgfw/internal/updater"
	"snapgfw/internal/web"
)

var version = "v0.5.0"

func main() {
	if len(os.Args) < 2 {
		runServe(os.Args[1:])
		return
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "set-password":
		runSetPassword(os.Args[2:])
	case "apply-preset":
		runApplyPreset(os.Args[2:])
	case "export-policy":
		runExportPolicy(os.Args[2:])
	case "import-policy":
		runImportPolicy(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("snapgfw %s\n", version)
	case "-h", "--help", "help":
		printUsage()
	default:
		if strings.HasPrefix(os.Args[1], "-") {
			runServe(os.Args[1:])
		} else {
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
			printUsage()
			os.Exit(2)
		}
	}
}

func printUsage() {
	fmt.Println(`SnapGFW — KVM + LXC/runman NAT DPI 防火墙与控制面板

用法:
  snapgfw serve [-config /etc/snapgfw/config.json]
  snapgfw set-password [-config /etc/snapgfw/config.json]   (从 stdin 读取密码)
  snapgfw apply-preset [-config /etc/snapgfw/config.json] <preset_id>
  snapgfw export-policy [-config /etc/snapgfw/config.json]
  snapgfw import-policy [-config /etc/snapgfw/config.json] <policy.json>
  snapgfw validate [-config /etc/snapgfw/config.json]
  snapgfw version`)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/snapgfw/config.json", "path to config.json")
	listenOverride := fs.String("listen", "", "override web panel listen address")
	bridgeOverride := fs.String("bridge", "", "override container bridge interface")
	noEngine := fs.Bool("panel-only", false, "run panel without NFQUEUE/nftables (dev/testing)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if *listenOverride != "" {
		cfg.ListenAddr = *listenOverride
	}
	if *bridgeOverride != "" {
		cfg.BridgeIface = *bridgeOverride
	}
	if cfg.AdminPassHash == "" {
		pass := randomPassword(16)
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("generate initial password: %v", err)
		}
		cfg.AdminPassHash = string(hash)
		if err := config.Save(*cfgPath, cfg); err != nil {
			log.Printf("warning: failed saving initial config: %v", err)
		} else {
			log.Printf("initialized panel login: user=%s password=%s (saved hash to %s)", cfg.AdminUser, pass, *cfgPath)
		}
	}

	policyPath := filepath.Join(cfg.DataDir, "policy.json")
	ps, err := store.NewPolicyStore(policyPath)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	auditPath := filepath.Join(cfg.DataDir, "audit.jsonl")
	as, err := store.NewAuditStore(auditPath, cfg.AuditRingCap, int64(cfg.AuditMaxFileMB)*1024*1024)
	if err != nil {
		log.Fatalf("init audit store: %v", err)
	}
	defer as.Close()

	disc := runman.NewDiscovery(cfg.RunmanDataDir)
	notif := notify.NewNotifier()
	defer notif.Close()

	qm := engine.NewQuarantineManager(cfg.NftTable, as, notif)
	eng := engine.New(cfg, ps.Get(), as, disc, qm)

	selfRestart := false
	restartCh := make(chan struct{}, 1)

	applyRuntime := func(c config.Config, pol model.Policy) error {
		if *noEngine {
			eng.UpdatePolicy(pol)
			return nil
		}
		if err := web.ApplyPolicyRuntime(c, pol, eng); err != nil {
			return err
		}
		if err := qm.ReapplyActive(); err != nil {
			log.Printf("warning: reapply active quarantine entries after nft reload: %v", err)
		}
		return nil
	}

	if !*noEngine {
		if err := netfilter.CheckHostPrereqs(); err != nil {
			log.Fatalf("host netfilter prerequisite check failed: %v", err)
		}
		if err := applyRuntime(cfg, ps.Get()); err != nil {
			log.Fatalf("apply initial nftables policy: %v", err)
		}
		defer func() {
			if selfRestart {
				return
			}
			if err := netfilter.DeleteTable(cfg.NftTable); err != nil {
				log.Printf("cleanup nft table %s: %v", cfg.NftTable, err)
			}
		}()
	}

	srv := web.NewServer(*cfgPath, cfg, ps, as, eng, disc, qm, notif)
	srv.SetApplyConfigHook(applyRuntime)
	srv.SetUpdater(updater.New(version, func() {
		select {
		case restartCh <- struct{}{}:
		default:
		}
	}))

	ps.OnChange(func(next model.Policy) error {
		return applyRuntime(srv.Config(), next)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Propagate root lifecycle cancellation into long-lived SSE connections
		// so Shutdown completes promptly instead of stalling self-update restarts.
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	// Periodic read-only refresh of runman-agent container inventory
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = disc.Refresh()
			}
		}
	}()

	// SIGHUP reloads policy.json from disk and re-applies nftables + DPI rules
	go func() {
		hupCh := make(chan os.Signal, 1)
		signal.Notify(hupCh, syscall.SIGHUP)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupCh:
				log.Printf("SIGHUP received, reloading policy and runman discovery")
				_ = disc.Refresh()
				if reloaded, err := store.NewPolicyStore(policyPath); err == nil {
					if err := ps.Update(reloaded.Get()); err != nil {
						log.Printf("reload apply failed: %v", err)
					}
				} else {
					log.Printf("reload read failed: %v", err)
				}
			}
		}
	}()

	errCh := make(chan error, 2)
	go func() {
		log.Printf("snapgfw %s web panel listening on http://%s (bridge=%s table=%s)", version, cfg.ListenAddr, cfg.BridgeIface, cfg.NftTable)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("web server: %w", err)
		}
	}()

	if !*noEngine {
		src := engine.NewNFQueueSource(cfg.QueueBase, cfg.NFQueueLen, cfg.SocketRcvBuf, cfg.ConnMarkAccept, cfg.ConnMarkDrop)
		go func() {
			log.Printf("snapgfw DPI engine starting (workers=%d queues=%d-%d)", cfg.Workers, cfg.QueueBase, cfg.QueueBase+3)
			if err := eng.Run(ctx, src); err != nil && ctx.Err() == nil {
				errCh <- fmt.Errorf("dpi engine: %w", err)
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigCh:
		log.Printf("shutting down gracefully...")
	case <-restartCh:
		selfRestart = true
		log.Printf("restarting into updated SnapGFW binary...")
	case err := <-errCh:
		log.Printf("fatal runtime error: %v", err)
	}
	cancel()
	shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shCancel()
	_ = httpSrv.Shutdown(shCtx)
	_ = httpSrv.Close()
}

func runSetPassword(args []string) {
	fs := flag.NewFlagSet("set-password", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/snapgfw/config.json", "path to config.json")
	_ = fs.Parse(args)

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		log.Fatalf("failed reading password from stdin: %v", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if len(pw) < 6 {
		log.Fatalf("password must be at least 6 characters")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("bcrypt: %v", err)
	}
	cfg.AdminPassHash = string(hash)
	if err := config.Save(*cfgPath, cfg); err != nil {
		log.Fatalf("save config: %v", err)
	}
	fmt.Println("password updated")
}

func runApplyPreset(args []string) {
	fs := flag.NewFlagSet("apply-preset", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/snapgfw/config.json", "path to config.json")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		log.Fatalf("usage: snapgfw apply-preset <anti_abuse>")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	ps, err := store.NewPolicyStore(filepath.Join(cfg.DataDir, "policy.json"))
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	if _, err := ps.ApplyPreset(fs.Arg(0), true); err != nil {
		log.Fatalf("apply preset: %v", err)
	}
	fmt.Printf("preset %s saved to %s (reload running daemon with SIGHUP if active)\n", fs.Arg(0), filepath.Join(cfg.DataDir, "policy.json"))
}

func runExportPolicy(args []string) {
	fs := flag.NewFlagSet("export-policy", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/snapgfw/config.json", "path to config.json")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	ps, err := store.NewPolicyStore(filepath.Join(cfg.DataDir, "policy.json"))
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	b, _ := json.MarshalIndent(ps.Get(), "", "  ")
	fmt.Println(string(b))
}

func runImportPolicy(args []string) {
	fs := flag.NewFlagSet("import-policy", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/snapgfw/config.json", "path to config.json")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		log.Fatalf("usage: snapgfw import-policy <policy.json>")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		log.Fatalf("read policy file: %v", err)
	}
	var pol model.Policy
	if err := json.Unmarshal(raw, &pol); err != nil {
		log.Fatalf("parse policy JSON: %v", err)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	ps, err := store.NewPolicyStore(filepath.Join(cfg.DataDir, "policy.json"))
	if err != nil {
		log.Fatalf("load store: %v", err)
	}
	if err := ps.Update(pol); err != nil {
		log.Fatalf("import policy: %v", err)
	}
	fmt.Println("policy imported successfully")
}

func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/snapgfw/config.json", "path to config.json")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config invalid: %v", err)
	}
	ps, err := store.NewPolicyStore(filepath.Join(cfg.DataDir, "policy.json"))
	if err != nil {
		log.Fatalf("policy invalid: %v", err)
	}
	script, err := netfilter.RenderNFT(cfg, ps.Get())
	if err != nil {
		log.Fatalf("nft render failed: %v", err)
	}
	fmt.Printf("OK (%d bytes nft script)\n", len(script))
}

func randomPassword(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
