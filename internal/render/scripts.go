package render

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/blanc-sh/blanc/internal/engine"
)

var safeSerial = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func quarantineScript(plan *engine.Plan) []byte {
	q := buildQuarantinePlan(plan)
	var b strings.Builder
	b.WriteString("#!/usr/bin/env sh\n# 鍵をかけ\n# 眠るアプリの\n# 夢を断つ\nset -eu\n")
	writePreamble(&b, plan.Device.Serial)
	if len(q.Targets) == 0 {
		b.WriteString("echo \"no quarantine targets\"\n")
		return []byte(b.String())
	}
	for _, target := range q.Targets {
		for _, command := range target.Commands {
			fmt.Fprintf(&b, "adb -s \"$serial\" shell %s\n", shellQuote(command))
		}
	}
	b.WriteString("echo \"quarantine applied to $serial\"\n")
	return []byte(b.String())
}

func rollbackScript(plan *engine.Plan) []byte {
	q := buildQuarantinePlan(plan)
	var b strings.Builder
	b.WriteString("#!/usr/bin/env sh\n# 朝の庭\n# 巻き戻す鍵を\n# 土に戻す\nset -eu\n")
	writePreamble(&b, plan.Device.Serial)
	written := 0
	for _, target := range q.Targets {
		for _, command := range target.Rollback {
			fmt.Fprintf(&b, "adb -s \"$serial\" shell %s\n", shellQuote(command))
			written++
		}
	}
	if written == 0 {
		b.WriteString("echo \"nothing to roll back\"\n")
		return []byte(b.String())
	}
	b.WriteString("echo \"rollback applied to $serial\"\n")
	return []byte(b.String())
}

func writePreamble(b *strings.Builder, serial string) {
	if safeSerial.MatchString(serial) && serial != "" {
		fmt.Fprintf(b, "serial=%s\n", shellQuote(serial))
	} else {
		b.WriteString("serial=\"${BLANC_SERIAL:-}\"\n")
		b.WriteString("if [ -z \"$serial\" ]; then echo \"set BLANC_SERIAL to the device serial\" >&2; exit 1; fi\n")
	}
	b.WriteString("command -v adb >/dev/null 2>&1 || { echo \"adb not found\" >&2; exit 1; }\n")
	b.WriteString("adb -s \"$serial\" get-state >/dev/null 2>&1 || { echo \"device not ready: $serial\" >&2; exit 1; }\n")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
