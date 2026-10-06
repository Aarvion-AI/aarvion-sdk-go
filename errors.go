package aarvion

import (
	"errors"
	"strings"
)

type AarvionError struct {
	Msg string
	Err error
}

func (e *AarvionError) Error() string { return e.Msg }

func (e *AarvionError) Unwrap() error { return e.Err }

type ConfigError struct {
	AarvionError
}

func (e *ConfigError) As(target any) bool {
	if t, ok := target.(**AarvionError); ok {
		*t = &e.AarvionError
		return true
	}
	return false
}

type SessionError struct {
	AarvionError
}

func (e *SessionError) As(target any) bool {
	if t, ok := target.(**AarvionError); ok {
		*t = &e.AarvionError
		return true
	}
	return false
}

type PolicyDenied struct {
	AarvionError
	PolicyID   string
	Reason     string
	HTTPStatus int
	PolicyIDs  []string
}

func (e *PolicyDenied) As(target any) bool {
	if t, ok := target.(**AarvionError); ok {
		*t = &e.AarvionError
		return true
	}
	return false
}

func NewPolicyDenied(policyID, reason string, httpStatus int, policyIDs []string) *PolicyDenied {
	ids := policyIDs
	if len(ids) == 0 {
		ids = []string{policyID}
	}
	return &PolicyDenied{
		AarvionError: AarvionError{Msg: policyID + ": " + reason},
		PolicyID:     policyID,
		Reason:       reason,
		HTTPStatus:   httpStatus,
		PolicyIDs:    ids,
	}
}

func newAarvionError(msg string) *AarvionError { return &AarvionError{Msg: msg} }

func newConfigError(msg string, cause error) *ConfigError {
	return &ConfigError{AarvionError{Msg: msg, Err: cause}}
}

func newSessionError(msg string, cause error) *SessionError {
	return &SessionError{AarvionError{Msg: msg, Err: cause}}
}

func IsAarvionError(err error) bool {
	var a *AarvionError
	return errors.As(err, &a)
}

type pyError struct {
	kind string
	msg  string
}

func (e *pyError) Error() string { return e.msg }

func (e *pyError) TypeName() string { return e.kind }

func pyValueError(msg string) error { return &pyError{kind: "ValueError", msg: msg} }

func pyTypeError(msg string) error { return &pyError{kind: "TypeError", msg: msg} }

func pyKeyError(key string) error { return &pyError{kind: "KeyError", msg: pyRepr(key)} }

func pyAttributeError(msg string) error { return &pyError{kind: "AttributeError", msg: msg} }

func pyRuntimeError(msg string) error { return &pyError{kind: "RuntimeError", msg: msg} }

func pyOverflowError(msg string) error { return &pyError{kind: "OverflowError", msg: msg} }

func isPyError(err error, kinds ...string) bool {
	var p *pyError
	if !errors.As(err, &p) {
		return false
	}
	for _, k := range kinds {
		if p.kind == k {
			return true
		}
		if k == "ValueError" && (p.kind == "JSONDecodeError" || p.kind == "UnicodeDecodeError") {
			return true
		}
	}
	return false
}

func pyErrorName(err error) string {
	var p *pyError
	if errors.As(err, &p) {
		return p.kind
	}
	var a *AarvionError
	if errors.As(err, &a) {
		switch err.(type) {
		case *ConfigError:
			return "aarvion.errors.ConfigError"
		case *SessionError:
			return "aarvion.errors.SessionError"
		case *PolicyDenied:
			return "aarvion.errors.PolicyDenied"
		}
		return "aarvion.errors.AarvionError"
	}
	name := strings.TrimPrefix(strings.TrimPrefix(typeName(err), "*"), "errors.")
	if name == "" {
		return "Error"
	}
	return name
}
