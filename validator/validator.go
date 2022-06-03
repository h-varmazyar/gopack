package validator

import (
	"github.com/go-playground/validator/v10"
)

var (
	validate = validator.New()
)

func Struct(s interface{}) error {
	if err := validate.Struct(s); err != nil {
		validationErrors, ok := err.(validator.ValidationErrors)
		if ok && validationErrors != nil {
			return validationErrors
		}
		return nil
	}
	return nil
}
