package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

func main() {
	router := gin.Default()

	// Initialize Casbin enforcer with updated model and policies
	enforcer, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		panic("Failed to create Casbin enforcer: " + err.Error())
	}

	policies := enforcer.GetPolicy()
	for _, p := range policies {
		fmt.Println(p)
	}

	// Middleware to check permissions
	authz := func(c *gin.Context) {
		role := c.GetHeader("role")
		obj := "/vm/" + c.Param("resource")
		act := c.Request.Method

		log.Printf("Enforcing with role: %s, obj: %s, act: %s\n", role, obj, act)

		if res, err := enforcer.Enforce(role, obj, act); err != nil || !res {
			log.Printf("Access denied or error: %v, error: %v\n", res, err)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}
		c.Next()
	}

	// API endpoints with authorization middleware
	router.GET("/vm/:resource", authz, getVM)
	router.POST("/vm/:resource", authz, createVM)
	router.PUT("/vm/:resource", authz, updateVM)
	router.DELETE("/vm/:resource", authz, deleteVM)

	router.Run(":8080")
}

func getVM(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "VM details accessed"})
}

func createVM(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "VM created"})
}

func updateVM(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "VM updated"})
}

func deleteVM(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "VM deleted"})
}
