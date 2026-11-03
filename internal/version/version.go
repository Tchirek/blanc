package version

var (
	Version = "dev"
	Commit  = "dev"
	Date    = "unknown"
)

func String() string {
	if Commit == "" || Commit == "dev" {
		return Version
	}
	return Version + " (" + Commit + ")"
}

func Full() string {
	out := "BLANC " + String()
	if Date != "" && Date != "unknown" {
		out += " built " + Date
	}
	return out
}
