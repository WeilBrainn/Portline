package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const githubRepo = "WeilBrainn/Portline"

type UpdateInfo struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	HasUpdate      bool   `json:"hasUpdate"`
	ReleaseURL     string `json:"releaseUrl,omitempty"`
	Error          string `json:"error,omitempty"`
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Draft   bool   `json:"draft"`
}

func parseSemverParts(v string) [3]int {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}

// isNewerVersion returns true when latest is strictly newer than current,
// or when numeric versions match and current is a prerelease while latest is stable.
func isNewerVersion(current, latest string) bool {
	c := parseSemverParts(current)
	l := parseSemverParts(latest)
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return strings.Contains(current, "-") && !strings.Contains(latest, "-")
}

func checkGitHubUpdate(ctx context.Context) UpdateInfo {
	info := UpdateInfo{CurrentVersion: version}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Portline/"+version)

	resp, err := (&http.Client{Timeout: 7 * time.Second}).Do(req)
	if err != nil {
		info.Error = "Не удалось связаться с GitHub."
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		info.LatestVersion = version
		info.ReleaseURL = fmt.Sprintf("https://github.com/%s/releases", githubRepo)
		return info
	}
	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("GitHub API вернул HTTP %d", resp.StatusCode)
		return info
	}

	var rel githubRelease
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 256*1024)).Decode(&rel); err != nil {
		info.Error = "Не удалось разобрать ответ GitHub."
		return info
	}
	if rel.TagName == "" {
		info.LatestVersion = version
		return info
	}

	latest := strings.TrimPrefix(rel.TagName, "v")
	info.LatestVersion = latest
	info.HasUpdate = isNewerVersion(version, latest)
	if strings.HasPrefix(rel.HTMLURL, "https://github.com/"+githubRepo) {
		info.ReleaseURL = rel.HTMLURL
	} else {
		info.ReleaseURL = fmt.Sprintf("https://github.com/%s/releases", githubRepo)
	}
	return info
}
