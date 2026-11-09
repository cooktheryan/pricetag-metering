package handler

import (
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func NewManagementHandler(store *storage.Store, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := r.Header.Get(cfg.UserHeader)
		route := strings.TrimPrefix(r.URL.Path, "/api/v1/management/")
		switch route {
		case "policy":
			NewQuotaAdminHandler(store).HandlePolicy(w, r)
		case "users":
			if r.Method == http.MethodGet {
				// Management must retain suspended accounts so administrators can
				// inspect and reactivate them. Ordinary directory views stay active-only.
				var users []storage.PartnerUser
				for offset := 0; ; offset += 100 {
					page, err := store.ListPartnerUsers(r.Context(), nil, true, 100, offset)
					if err != nil {
						http.Error(w, "user query failed", 500)
						return
					}
					users = append(users, page.Users...)
					if !page.HasMore {
						break
					}
				}
				type managedUser struct {
					adminPartnerUserResponse
					Logins []string `json:"logins"`
				}
				rows := make([]managedUser, 0, len(users))
				for _, u := range users {
					logins, err := store.ListPartnerUsernames(r.Context(), u.UserID)
					if err != nil {
						http.Error(w, "user query failed", 500)
						return
					}
					rows = append(rows, managedUser{adminPartnerUser(u), logins})
				}
				writeJSON(w, rows)
				return
			}
			if r.Method != http.MethodPut {
				http.Error(w, "method not allowed", 405)
				return
			}
			var body storage.LoginProvision
			if !decodeJSON(w, r, &body) {
				return
			}
			if body.Subject == actor && ((body.Active != nil && !*body.Active) || (body.Role != "" && body.Role != storage.PartnerRoleSuperAdmin)) {
				http.Error(w, "cannot remove own management access", 400)
				return
			}
			user, err := store.ProvisionLogin(r.Context(), actor, body)
			if err != nil {
				http.Error(w, "user update rejected", 400)
				return
			}
			writeJSON(w, adminPartnerUser(user))
		case "budgets":
			if r.Method == http.MethodGet && r.URL.RawQuery != "" {
				query := r.URL.Query()
				for name, values := range query {
					if (name != "offset" && name != "search" && name != "subject" && name != "limit") || len(values) != 1 {
						http.Error(w, "invalid budget query", 400)
						return
					}
				}
				offset := 0
				if raw, ok := query["offset"]; ok {
					var err error
					offset, err = strconv.Atoi(raw[0])
					if err != nil || offset < 0 || offset > 1000000 {
						http.Error(w, "invalid offset", 400)
						return
					}
				}
				if len(query.Get("search")) > 128 || len(query.Get("subject")) > 128 {
					http.Error(w, "invalid search", 400)
					return
				}
				limit := 20
				if raw, ok := query["limit"]; ok {
					var err error
					limit, err = strconv.Atoi(raw[0])
					if err != nil || (limit != 5 && limit != 20 && limit != 50) {
						http.Error(w, "invalid limit", 400)
						return
					}
				}
				rows, more, err := store.UserBudgetOverridesPage(r.Context(), query.Get("search"), query.Get("subject"), limit, offset)
				if err != nil {
					http.Error(w, "budget query failed", 500)
					return
				}
				policy, err := store.GetQuotaPolicy(r.Context())
				if err != nil {
					http.Error(w, "policy query failed", 500)
					return
				}
				writeJSON(w, map[string]any{"data": rows, "has_more": more, "default_monthly_usd": policy.DefaultMonthlyUSD})
				return
			}
			if r.Method == http.MethodGet {
				rows, err := store.ListQuotaOverrides(r.Context())
				if err != nil {
					http.Error(w, "budget query failed", 500)
					return
				}
				if rows == nil {
					rows = []storage.QuotaOverride{}
				}
				writeJSON(w, rows)
				return
			}
			var body struct {
				Subject    string  `json:"subject"`
				MonthlyUSD float64 `json:"monthly_usd"`
			}
			if r.Method != http.MethodPut && r.Method != http.MethodDelete {
				http.Error(w, "method not allowed", 405)
				return
			}
			if !decodeJSON(w, r, &body) {
				return
			}
			if strings.TrimSpace(body.Subject) == "" || len(body.Subject) > 128 {
				http.Error(w, "invalid subject", 400)
				return
			}
			var err error
			if r.Method == http.MethodDelete {
				err = store.DeleteQuotaOverride(r.Context(), actor, "user", body.Subject)
			} else {
				if math.IsNaN(body.MonthlyUSD) || math.IsInf(body.MonthlyUSD, 0) || body.MonthlyUSD < .01 || body.MonthlyUSD > 10000 || math.Abs(body.MonthlyUSD*100-math.Round(body.MonthlyUSD*100)) > 1e-8 {
					http.Error(w, "monthly_usd must be 0.01–10000 in whole cents", 400)
					return
				}
				err = store.UpsertQuotaOverride(r.Context(), actor, "user", body.Subject, body.MonthlyUSD)
			}
			if err != nil {
				http.Error(w, "budget update failed", 500)
				return
			}
			writeJSON(w, map[string]bool{"updated": true})
		case "prices":
			if r.Method == http.MethodGet {
				rows, err := store.GetCurrentPricing(r.Context())
				if err != nil {
					http.Error(w, "price query failed", 500)
					return
				}
				writeJSON(w, rows)
				return
			}
			if r.Method != http.MethodPut {
				http.Error(w, "method not allowed", 405)
				return
			}
			var body storage.ManagedPrice
			if !decodeJSON(w, r, &body) {
				return
			}
			if err := store.SetManagedPrice(r.Context(), actor, body); err != nil {
				http.Error(w, "price update rejected", 400)
				return
			}
			writeJSON(w, map[string]bool{"updated": true})
		default:
			http.NotFound(w, r)
		}
	}
}
