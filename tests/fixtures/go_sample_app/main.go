package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func insecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func runHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	user := r.URL.Query().Get("user")
	_, _ = db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", user))
	_ = exec.Command("sh", "-c", "echo "+user).Run()
	data, _ := os.ReadFile(filepath.Join("/srv/public", r.URL.Query().Get("file")))
	_, _ = http.Get(r.URL.Query().Get("url"))
	_, _ = w.Write(data)
}
