package dkim

import (
	"fmt"
)

type DError struct {
	status   Status
	message  string
	internal error
}

func NewDkimError(status Status, message string) *DError {
	return &DError{status: status, message: message}
}

func NewSyntaxError(err error) *DError {
	return &DError{
		status:   StatusPermFail,
		message:  "signature syntax error",
		internal: err,
	}
}

func WrapError(err error, status Status, message string) *DError {
	return &DError{status: status, message: message, internal: err}
}

func (t *DError) Error() string {
	if t.internal != nil {
		return fmt.Sprintf("dkim(%s): %s: %s", t.status, t.message, t.internal.Error())
	}
	return fmt.Sprintf("dkim(%s): %s", t.status, t.message)
}

func (t *DError) Unwrap() error {
	return t.internal
}

// todo: 让错误可以包装错误发生的位置, 比如当签名tag出现错误时, 报错的时候可以以固定的格式包装错误位置
