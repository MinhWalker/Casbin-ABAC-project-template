package main

import (
	"casbin-ABAC-project/middleware"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetVM(t *testing.T) {
	router := gin.Default()
	enforcer, _ := casbin.NewEnforcer("model.conf", "policy.csv")
	router.GET("/vm/:resource", middleware.Authz(enforcer), getVM) // Use the same authz middleware and handler

	// Test with Admin role
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/vm/resource1", nil)
	req.Header.Add("role", "admin") // Set role header
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code) // Check if admin can access
	assert.Contains(t, w.Body.String(), "VM details accessed")

	// Test with User role
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/vm/resource1", nil)
	req.Header.Add("role", "user") // Change role to user
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code) // Check if user is denied
}
