package version

var (
	Version = "0.2.0"
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
	return "BLANC " + String() + " built " + Date
}
