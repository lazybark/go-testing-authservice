package api

// Logic in http_routes is pretty simple. In real-life project it would be much stronger, of course.

import (
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/lazybark/go-testing-authservice/pkg/api/hthandlers"
	"github.com/lazybark/go-testing-authservice/pkg/api/resp"
)

// getChiRoutes returns chi.Mux with pre-defined routes for HTTP server.
func (s *Server) getChiRoutes(r *chi.Mux) *chi.Mux {
	r.NotFound(resp.NotFoundHandler)
	r.Use(middleware.RealIP)

	r.Route("/api/users", func(r chi.Router) {
		r.Post("/register", hthandlers.Register(s.ds))
		r.Post("/login", hthandlers.Login(s.jwtSecret, s.maxWrongLogins, s.ds))
		r.Get("/check_token/{token}", hthandlers.CheckToken(s.jwtSecret))
		r.Post("/get_token", hthandlers.GetToken(s.jwtSecret))
	})

	return r
}
