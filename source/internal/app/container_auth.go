package app

import (
	"net/http"
)

func (a *App) requireContainerAdmin(w http.ResponseWriter, r *http.Request) bool {
	u := currentUser(r)
	if u == nil || u.Role != "admin" {
		writeErr(w, http.StatusForbidden, "需要管理员权限")
		return false
	}
	return true
}
