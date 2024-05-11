package model

type Failure struct {
	Error any `json:"error"`
}

func Fail(code uint, message string) (int, *Failure) {
	return int(code), &Failure{struct {
		Code    uint   `json:"code"`
		Message string `json:"message"`
	}{code, message}}
}
