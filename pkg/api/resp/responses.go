package resp

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Response is returned to requester in HTTP server.
type Response struct {
	Success  bool `json:"success"`
	Status   int  `json:"status"`
	Response any  `json:"response"`
}

// Some hardcoded vars to make general writes simpler and faster (avoid JSON encoding when message is obvious).
var (
	ErrInternalMessage string = "internal_server_error"
	RespOKMessage      string = "ok"

	errInternal   = []byte(fmt.Sprintf(`{"success":false,"status":500,"response":"%s"}`, ErrInternalMessage))
	errNotFound   = []byte(`{"success":false,"status":404,"response":"not_found"}`)
	errBadRequest = []byte(`{"success":false,"status":400,"response":"bad_request"}`)
	respOK        = []byte(fmt.Sprintf(`{"success":true,"status":200,"response":"%s"}`, RespOKMessage))
)

// WriteSuccess writes success response into w.
func WriteSuccess(w http.ResponseWriter, response any) error {
	r := Response{
		Success:  true,
		Status:   200,
		Response: response,
	}

	bts, err := json.Marshal(r)
	if err != nil {
		RespErrorInternal(w) // Still need to tell something

		return fmt.Errorf("[SuccessResponse] %w", err)
	}

	_, _ = w.Write(bts)

	return nil
}

// WriteError writes error response into w.
func WriteError(w http.ResponseWriter, status int, response any) error {
	r := Response{
		Success:  false,
		Status:   status,
		Response: response,
	}

	bts, err := json.Marshal(r)
	if err != nil {
		RespErrorInternal(w) // Still need to tell something

		return fmt.Errorf("[SuccessResponse] %w", err)
	}

	w.WriteHeader(status)
	_, _ = w.Write(bts)

	return nil
}

// RespErrorNotFound writes not found response into w.
func RespErrorNotFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(errNotFound)
}

// RespErrorInternal writes internal error response into w.
func RespErrorInternal(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(errInternal)
}

// RespErrorBadRequest writes bad request response into w.
func RespErrorBadRequest(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(errBadRequest)
}

// RespOK writes "ok" response into w.
func RespOK(w http.ResponseWriter) {
	_, _ = w.Write(respOK)
}

// NotFoundHandler returns 404 error to requester.
func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	RespErrorNotFound(w)
}
