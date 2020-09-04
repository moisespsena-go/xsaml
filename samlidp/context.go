package samlidp

import (
	"context"
	"net/http"
	"strings"
)

const (
	LoginFormUserOptions contextKey = iota
	SubPath
)

type contextKey uint8

func ContextGetLoginFormDataInputOptions(ctx context.Context) (opts *LoginFormDataInputOptions) {
	if v := ctx.Value(LoginFormUserOptions); v != nil {
		if v, ok := v.(*LoginFormDataInputOptions); ok {
			opts = v
		}
	}
	return
}

func ContextGetOrSetLoginFormDataInputOptions(ctx context.Context) (c context.Context, opts *LoginFormDataInputOptions) {
	c = ctx
	if opts = ContextGetLoginFormDataInputOptions(ctx); opts == nil {
		opts = &LoginFormDataInputOptions{}
		c = context.WithValue(c, LoginFormUserOptions, opts)
	}
	return
}

func subPath(pth string, next func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub := strings.TrimPrefix(r.URL.Path, pth)
		if sub == "/" {
			sub = ""
		}
		r.WithContext(context.WithValue(r.Context(), SubPath, sub))
		next(w, r)
	}
}

func ContextGetSubPath(ctx context.Context) (sub string) {
	if value := ctx.Value(SubPath); value != nil {
		sub = value.(string)
	}
	return
}
