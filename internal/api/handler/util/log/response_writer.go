package logutil

import "net/http"

type CustomResponseWriter struct {
	http.ResponseWriter
	StatusCode int
}

func (rw *CustomResponseWriter) WriteHeader(statusCode int) {
	rw.StatusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}
