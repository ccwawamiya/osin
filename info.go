package osin

import (
	"net/http"
	"time"
	"strconv"
)

// InfoRequest is a request for information about some AccessData
type InfoRequest struct {
	Code       string      // Code to look up
	AccessData *AccessData // AccessData associated with Code
}

// HandleInfoRequest is an http.HandlerFunc for server information
// NOT an RFC specification.
func (s *Server) HandleInfoRequest(w *Response, r *http.Request) *InfoRequest {
	r.ParseForm()
	bearer := CheckBearerAuth(r)
	if bearer == nil {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	// generate info request
	ret := &InfoRequest{
		Code: bearer.Code,
	}

	if ret.Code == "" {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	var err error

	// load access data
	ret.AccessData, err = w.Storage.LoadAccess(ret.Code)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if ret.AccessData == nil {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}
	if ret.AccessData.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.Client.GetRedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.IsExpiredAt(s.Now()) {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	return ret
}

// FinishInfoRequest finalizes the request handled by HandleInfoRequest
func (s *Server) FinishInfoRequest(w *Response, r *http.Request, ir *InfoRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	w.Output["client_id"] = ir.AccessData.Client.GetId()
	w.Output["access_token"] = ir.AccessData.AccessToken
	//注释token_type,暂时不知有什么用处
	//w.Output["token_type"] = s.Config.TokenType
	w.Output["expires_in"] = ir.AccessData.CreatedAt.Add(time.Duration(ir.AccessData.ExpiresIn)*time.Second).Sub(s.Now()) / time.Second
	if ir.AccessData.RefreshToken != "" {
		w.Output["refresh_token"] = ir.AccessData.RefreshToken
	}
	if ir.AccessData.Scope != "" {
		w.Output["scope"] = ir.AccessData.Scope
	}
	if ir.AccessData.UserData != "" {
		w.Output["user_id"],_ = strconv.ParseInt(ir.AccessData.UserData.(string),10,64)
	}
}
