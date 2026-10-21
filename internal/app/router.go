package app

import (
	"io/fs"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type App struct {
	cfg    Config
	store  *Store
	jwtKey []byte
}

func New(cfg Config) (*App, error) {
	st, err := OpenStore(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, store: st, jwtKey: []byte(cfg.JWTSecret)}
	if err := a.ensureAdmin(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *App) ensureAdmin() error {
	n, err := a.store.CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	pass := a.cfg.AdminPass
	if pass == "" {
		pass = "hcd10086"
		log.Printf("======================================================")
		log.Printf("  初始管理员已创建")
		log.Printf("  用户名: %s", a.cfg.AdminUser)
		log.Printf("  密码  : %s", pass)
		log.Printf("  (请在登录后立即修改密码)")
		log.Printf("======================================================")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return a.store.CreateUser(a.cfg.AdminUser, string(h), "admin")
}

func (a *App) Router(static fs.FS) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)

	authed := map[string]http.HandlerFunc{
		"GET /api/v1/auth/me":          a.handleMe,
		"PUT /api/v1/auth/password":    a.handlePassword,
		"GET /api/v1/settings":         a.handleGetSettings,
		"PUT /api/v1/settings":         a.handleUpdateSettings,
		"GET /api/v1/proxies":          a.handleListProxies,
		"POST /api/v1/proxies":         a.handleCreateProxy,
		"PUT /api/v1/proxies/{id}":     a.handleUpdateProxy,
		"DELETE /api/v1/proxies/{id}":  a.handleDeleteProxy,
		"GET /api/v1/config/preview":   a.handlePreview,
		"POST /api/v1/config/publish":  a.handlePublish,
		"GET /api/v1/config/versions":  a.handleVersions,
		"POST /api/v1/config/rollback": a.handleRollback,
		"GET /api/v1/monitor/overview": a.handleOverview,
"POST /api/v1/mihomo/update":   a.handleUpdateMihomo,
	}
	for pat, h := range authed {
		mux.HandleFunc(pat, a.auth(h))
	}

	mux.Handle("/", http.FileServer(http.FS(static)))
	return withRecover(mux)
}

func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if e := recover(); e != nil {
				log.Printf("panic: %v", e)
				writeErr(w, 500, "服务器内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
