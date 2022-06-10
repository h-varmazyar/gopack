package mux

import (
	"github.com/gorilla/mux"
	"net/http"
)

func NewRouter(strictSlash bool) *mux.Router {
	return mux.NewRouter().StrictSlash(strictSlash)
}

func PathParam(req *http.Request, name string) string {
	return mux.Vars(req)[name]
}

func QueryParam(req *http.Request, name string) []string {
	values, ok := req.URL.Query()[name]
	if !ok {
		return make([]string, 0)
	}
	return values
}
