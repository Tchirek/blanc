package audit

import (
	"strings"
)

// 秘め事を
// 人は言葉に
// 見分けたり
var dataTypeOrder = []string{
	"location", "contacts", "sms", "calls", "mic", "camera",
	"screen", "apps", "identity", "files", "calendar", "accounts",
}

var dataTypeAliases = map[string]string{
	"位置": "location", "定位": "location", "location": "location",
	"通讯录": "contacts", "联系人": "contacts", "contacts": "contacts",
	"短信": "sms", "sms": "sms",
	"通话记录": "calls", "通话": "calls", "calls": "calls",
	"麦克风": "mic", "录音": "mic", "mic": "mic", "microphone": "mic",
	"相机": "camera", "摄像头": "camera", "camera": "camera",
	"屏幕": "screen", "录屏": "screen", "screen": "screen",
	"应用列表": "apps", "apps": "apps",
	"设备标识": "identity", "设备标识符": "identity", "identity": "identity",
	"文件/相册": "files", "文件": "files", "相册": "files", "files": "files",
	"日历": "calendar", "calendar": "calendar",
	"账号": "accounts", "账户": "accounts", "accounts": "accounts",
}

var categoryAliases = map[string]string{
	"遥测/统计": "telemetry", "遥测": "telemetry", "统计": "telemetry", "telemetry": "telemetry",
	"广告": "ads", "ads": "ads",
	"安全/杀毒": "security", "安全": "security", "security": "security",
	"AI/语音": "ai_voice", "ai/语音": "ai_voice", "ai_voice": "ai_voice",
	"定位/地图": "location", "定位": "location", "location": "location",
	"推送": "push", "push": "push",
	"应用商店": "app_store", "app_store": "app_store",
	"输入法": "input_method", "input_method": "input_method",
	"支付": "payment", "payment": "payment",
	"金融": "finance", "finance": "finance",
	"购物": "shopping", "shopping": "shopping",
	"影音": "media", "media": "media",
	"社交": "social", "social": "social",
	"游戏": "game", "game": "game",
	"工具": "tool", "tool": "tool",
	"运营商": "carrier", "carrier": "carrier",
	"系统": "system", "system": "system",
	"其他": "other", "other": "other",
}

var permissionData = map[string][]string{
	"ACCESS_FINE_LOCATION":                {"location"},
	"ACCESS_COARSE_LOCATION":              {"location"},
	"ACCESS_BACKGROUND_LOCATION":          {"location"},
	"READ_CONTACTS":                       {"contacts"},
	"READ_SMS":                            {"sms"},
	"RECEIVE_SMS":                         {"sms"},
	"READ_CALL_LOG":                       {"calls"},
	"READ_PHONE_STATE":                    {"identity"},
	"READ_PRIVILEGED_PHONE_STATE":         {"identity"},
	"RECORD_AUDIO":                        {"mic"},
	"CAPTURE_AUDIO_OUTPUT":                {"mic"},
	"CAPTURE_VOICE_COMMUNICATION_OUTPUT":  {"mic"},
	"CAMERA":                              {"camera"},
	"FOREGROUND_SERVICE_MEDIA_PROJECTION": {"screen"},
	"QUERY_ALL_PACKAGES":                  {"apps"},
	"PACKAGE_USAGE_STATS":                 {"apps"},
	"MANAGE_EXTERNAL_STORAGE":             {"files"},
	"READ_MEDIA_IMAGES":                   {"files"},
	"READ_MEDIA_VIDEO":                    {"files"},
	"READ_EXTERNAL_STORAGE":               {"files"},
	"READ_CALENDAR":                       {"calendar"},
	"GET_ACCOUNTS":                        {"accounts"},
}

func NormalizeDataType(value string) (string, bool) {
	slug, ok := dataTypeAliases[strings.ToLower(strings.TrimSpace(value))]
	return slug, ok
}

func NormalizeCategory(value string) (string, bool) {
	slug, ok := categoryAliases[strings.ToLower(strings.TrimSpace(value))]
	return slug, ok
}

func DataTypesFromLabels(labels []string) []string {
	set := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		if slug, ok := NormalizeDataType(label); ok {
			set[slug] = struct{}{}
		}
	}
	return orderedDataTypes(set)
}

func DataTypesFromPermissions(perms []string) []string {
	set := make(map[string]struct{})
	for _, perm := range perms {
		name := perm
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		for _, slug := range permissionData[name] {
			set[slug] = struct{}{}
		}
	}
	return orderedDataTypes(set)
}

func KnownDataTypes() []string {
	return append([]string(nil), dataTypeOrder...)
}

func OrderedDataTypes(set map[string]struct{}) []string {
	return orderedDataTypes(set)
}

func orderedDataTypes(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for _, slug := range dataTypeOrder {
		if _, ok := set[slug]; ok {
			out = append(out, slug)
		}
	}
	return out
}
