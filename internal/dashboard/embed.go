package dashboard

import "embed"

//go:embed dashboard.html manager.html admin.html routing.html login.html user-dashboard.html welcome.html coming-soon.html onboarding.html account.html terms.html
var FS embed.FS
