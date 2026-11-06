package vulndb

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

// BaseURL is the public OSV bulk export bucket.
const BaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// maxDownload caps a single ecosystem export (npm is the largest, a few hundred MB).
const maxDownload = 3 << 30

// Update downloads the OSV export for each ecosystem and rebuilds its index.
// This is the only place where SecureProjects contacts the network on its
// own, and it only sends HTTP GET requests for public files: no project
// data is ever transmitted.
func Update(ctx context.Context, dir string, ecosystems []string, log *slog.Logger) error {
	client := &http.Client{Timeout: 60 * time.Minute}
	var failed []string
	for _, eco := range ecosystems {
		start := time.Now()
		log.Info("downloading OSV export", "ecosystem", eco)
		if err := updateOne(ctx, client, dir, eco); err != nil {
			log.Error("OSV update failed", "ecosystem", eco, "error", err)
			failed = append(failed, eco)
			continue
		}
		log.Info("OSV index ready", "ecosystem", eco, "took", time.Since(start).Round(time.Second))
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to update: %v", failed)
	}
	return nil
}

func updateOne(ctx context.Context, client *http.Client, dir, eco string) error {
	u := BaseURL + "/" + url.PathEscape(eco) + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "secureprojects-db-update")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "download-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDownload+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxDownload {
		return fmt.Errorf("export for %s exceeds %d bytes", eco, int64(maxDownload))
	}
	ix, err := BuildFromZip(tmp.Name(), eco)
	if err != nil {
		return err
	}
	return ix.Save(dir)
}
