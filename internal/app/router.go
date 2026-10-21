package app

import (
	"io/fs"
	"log/slog"
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
	a.ensureAdmin()
	return a, nil
}

func (a *App) ensureAdmin() error {
	n, _ := a.store.CountUsers()
	if n > 0 {
		return nil
	}
	pass := a.cfg.AdminPass
	if pass == "" {
		pass = "hcd10086"
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	return a.store.CreateUser(a.cfg.AdminUser, string(h), "admin")
}

func (a *App) Router(static fs.FS) http.Handler {
	mux := http.NewServeMux()

	// ================= 公共接口（无需鉴权） =================
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.HandleFunc("GET /api/v1/subscribe", a.handleSubscribe)
	mux.HandleFunc("GET /api/v1/backup", a.handleDownloadBackup)
	
	// 核心新增：Agent 自动注册接口
	mux.HandleFunc("POST /api/v1/agent/register", a.handleAgentRegister)

	// ================= 管理接口（需 JWT 鉴权） =================
	authed := map[string]http.HandlerFunc{
		"GET /api/v1/auth/me":          a.handleMe,
		"PUT /api/v1/auth/password":    a.handlePassword,
		"GET /api/v1/settings":         a.handleGetSettings,
		"PUT /api/v1/settings":         a.handleUpdateSettings,
		"GET /api/v1/proxies":          a.handleListProxies,
		"POST /api/v1/proxies":         a.handleCreateProxy,
		"POST /api/v1/proxies/import":  a.handleImportProxies,
		"PUT /api/v1/proxies/{id}":     a.handleUpdateProxy,
		"DELETE /api/v1/proxies/{id}":  a.handleDeleteProxy,
		"GET /api/v1/config/preview":   a.handlePreview,
		"POST /api/v1/config/publish":  a.handlePublish,
		"GET /api/v1/config/versions":  a.handleVersions,
		"POST /api/v1/config/rollback": a.handleRollback,
		"GET /api/v1/monitor/overview": a.handleOverview,
		"GET /api/v1/monitor/traffic":  a.handleMonitorTraffic,
		"POST /api/v1/mihomo/update":   a.handleUpdateMihomo,
		"GET /api/v1/logs":             a.handleGetLogs,
		"POST /api/v1/restore":         a.handleRestoreBackup,
	}
	for pat, h := range authed {
		mux.HandleFunc(pat, a.auth(h))
	}

	// ================= 静态资源 =================
	mux.Handle("/", http.FileServer(http.FS(static)))

	return withRecover(mux)
}

// ================= 错误日志与崩溃捕获中间件 =================

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if e := recover(); e != nil {
				slog.Error("系统发生 Panic 崩溃", "error", e, "path", r.URL.Path)
				writeErr(w, 500, "服务器内部错误")
			}
		}()

		sw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		// 记录 4xx / 5xx 异常请求
		if sw.status >= 400 {
			slog.Warn("HTTP 请求异常",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"ip", r.RemoteAddr,
			)
		}
	})
}
