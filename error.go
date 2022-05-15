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

func NewSignError(msg string) *DError {
	return &DError{status: StatusSignFail, message: msg}
}

func WrapError(err error, status Status, message string) *DError {
	return &DError{status: status, message: message, internal: err}
}

func (t *DError) Error() string {
	var msg string
	if t.internal != nil {
		msg = fmt.Sprintf("%s: %s", t.message, t.internal.Error())
	} else {
		msg = fmt.Sprintf("%s", t.message)
	}
	if t.status == StatusSignFail {
		msg = "dkim: " + msg
	} else {
		msg = fmt.Sprintf("dkim(%s): ", t.status) + msg
	}
	return msg
}

func (t *DError) Unwrap() error {
	return t.internal
}

// todo: 让错误可以包装错误发生的位置, 比如当签名tag出现错误时, 报错的时候可以以固定的格式包装错误位置
