package dashboard

import "embed"

//go:embed dashboard.html manager.html admin.html routing.html login.html user-dashboard.html welcome.html coming-soon.html account.html management-admin-*.html management-*.js
var FS embed.FS
