//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"
	"time"

	"github.com/Tchirek/blanc/internal/version"
	"github.com/Tchirek/blanc/internal/webapi"
)

// 窓の内
// 外へ一字も
// 送らざり
func main() {
	js.Global().Set("blancCompile", js.FuncOf(compile))
	js.Global().Set("blancVersion", version.String())
	if ready := js.Global().Get("blancReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {}
}

// 受けし紙
// 網に編み替え
// 文で返す
func compile(_ js.Value, args []js.Value) (out any) {
	defer func() {
		if r := recover(); r != nil {
			out = reply(nil, fmt.Errorf("internal error: %v", r))
		}
	}()
	if len(args) == 0 || args[0].Type() != js.TypeObject {
		return reply(nil, fmt.Errorf("blancCompile(files, policy): files must be an object"))
	}
	files := make(map[string][]byte)
	keys := js.Global().Get("Object").Call("keys", args[0])
	for i := 0; i < keys.Length(); i++ {
		name := keys.Index(i).String()
		value := args[0].Get(name)
		if value.Type() == js.TypeString {
			files[name] = []byte(value.String())
			continue
		}
		buf := make([]byte, value.Get("length").Int())
		js.CopyBytesToGo(buf, value)
		files[name] = buf
	}
	policyText := ""
	if len(args) > 1 && args[1].Type() == js.TypeString {
		policyText = args[1].String()
	}
	result, err := webapi.Compile(files, policyText, time.Now())
	return reply(result, err)
}

func reply(result *webapi.Result, err error) string {
	body := map[string]any{"ok": err == nil}
	if err != nil {
		body["error"] = err.Error()
	} else {
		body["result"] = result
	}
	raw, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		return `{"ok":false,"error":"encode result"}`
	}
	return string(raw)
}
