package logutil

import (
	"fmt"
	"log/slog"
	"net/url"
)

func InfoLogger(reqURL url.URL, method string) func(rw *CustomResponseWriter, msgs ...string) {
	requestInfo := fmt.Sprintf("%s %s", method, reqURL.String())
	return func(rw *CustomResponseWriter, msgs ...string) {
		args := []any{slog.Int("status", rw.StatusCode)}
		if len(msgs) != 0 {
			args = append(args, slog.String("msg", fmt.Sprint(msgs)))
		}
		slog.Info(requestInfo, args...)
	}
}
