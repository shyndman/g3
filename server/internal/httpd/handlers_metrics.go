package httpd

import (
	"fmt"
	"log"
	"net/http"

	"g3/internal/store"
)

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

const storageGauges = `# HELP g3_buckets Number of S3 buckets.
# TYPE g3_buckets gauge
g3_buckets %d
# HELP g3_objects Number of S3 objects.
# TYPE g3_objects gauge
g3_objects %d
# HELP g3_object_bytes Total bytes in completed S3 objects.
# TYPE g3_object_bytes gauge
g3_object_bytes %d
# HELP g3_drive_accounts Number of linked Google Drive accounts.
# TYPE g3_drive_accounts gauge
g3_drive_accounts %d
# HELP g3_drive_connected_accounts Number of Drive accounts marked connected.
# TYPE g3_drive_connected_accounts gauge
g3_drive_connected_accounts %d
# HELP g3_drive_usage_bytes Stored Drive usage across linked accounts, including non-G3 files.
# TYPE g3_drive_usage_bytes gauge
g3_drive_usage_bytes %d
# HELP g3_drive_quota_bytes Stored Drive quota across linked accounts.
# TYPE g3_drive_quota_bytes gauge
g3_drive_quota_bytes %d
# HELP g3_drive_account_g3_bytes Bytes stored by G3 on a Drive account, including staged multipart parts.
# TYPE g3_drive_account_g3_bytes gauge
`

func (a *api) getMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	stats, err := a.store.Stats()
	if err != nil {
		metricsError(w, "read storage totals", err)
		return
	}
	accountIDs, err := a.store.DriveAccountIDs()
	if err != nil {
		metricsError(w, "list Drive account IDs", err)
		return
	}
	usage, err := a.store.UsageByAccount(store.FailOnUnreadableManifests)
	if err != nil {
		metricsError(w, "measure G3 bytes by Drive account", err)
		return
	}

	w.Header().Set("Content-Type", metricsContentType)
	_, _ = fmt.Fprintf(w, storageGauges, stats.Buckets, stats.Objects, stats.TotalSize,
		stats.Accounts, stats.ConnectedAccounts, stats.PoolUsage, stats.PoolLimit)
	for _, id := range accountIDs {
		// Drive account IDs are generated as hex, so they need no label escaping.
		_, _ = fmt.Fprintf(w, "g3_drive_account_g3_bytes{account_id=\"%s\"} %d\n", id, usage[id])
	}
}

func metricsError(w http.ResponseWriter, operation string, err error) {
	log.Printf("metrics scrape: %s: %v", operation, err)
	http.Error(w, "could not collect metrics", http.StatusInternalServerError)
}
