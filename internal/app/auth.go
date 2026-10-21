package app

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ctxKey string

const userKey ctxKey = "user"

func (a *App) signToken(u *User) (string, error) {
	claims := jwt.MapClaims{
		"sub":  u.ID,
		"usr":  u.Username,
		"role": u.Role,
		"exp":  time.Now().Add(12 * time.Hour).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.jwtKey)
}

func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeErr(w, 401, "未登录")
			return
		}
		t, err := jwt.Parse(strings.TrimPrefix(h, "Bearer "), func(t *jwt.Token) (any, error) {
			return a.jwtKey, nil
		}, jwt.WithValidMethods([]string{"HS256"}))
		if err != nil || !t.Valid {
			writeErr(w, 401, "登录已失效，请重新登录")
			return
		}
		claims, _ := t.Claims.(jwt.MapClaims)
		u := &User{}
		if id, ok := claims["sub"].(float64); ok {
			u.ID = int64(id)
		}
		u.Username, _ = claims["usr"].(string)
		u.Role, _ = claims["role"].(string)
		ctx := context.WithValue(r.Context(), userKey, u)
		next(w, r.WithContext(ctx))
	}
}

func currentUser(r *http.Request) *User {
	if u, ok := r.Context().Value(userKey).(*User); ok {
		return u
	}
	return nil
}
