package routers

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	_ "github.com/nexodus-io/nexodus/internal/docs"
	"github.com/nexodus-io/nexodus/internal/handlers"
	agent "github.com/nexodus-io/nexodus/pkg/oidcagent"
	"github.com/open-policy-agent/opa/storage"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"
)

const name = "github.com/nexodus-io/nexodus/internal/routers"

func NewAPIRouter(
	ctx context.Context,
	logger *zap.SugaredLogger,
	api *handlers.API,
	clientIdWeb string,
	clientIdCli string,
	oidcURL string,
	oidcBackchannel string,
	insecureTLS bool,
	browserFlow *agent.OidcAgent,
	deviceFlow *agent.OidcAgent,
	store storage.Store) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	loggerMiddleware := ginzap.GinzapWithConfig(logger.Desugar(), &ginzap.Config{TimeFormat: time.RFC3339, UTC: true, TraceID: true})
	r.Use(otelgin.Middleware(name))
	r.Use(ginzap.RecoveryWithZap(logger.Desugar(), true))

	newPrometheus().Use(r)

	device := r.Group("/device", loggerMiddleware)
	{
		device.POST("/login/start", deviceFlow.DeviceStart)
	}
	web := r.Group("/web", loggerMiddleware)
	{
		web.Use(browserFlow.OriginVerifier())
		web.Use(browserFlow.CookieSessionMiddleware())
		web.POST("/login/start", browserFlow.LoginStart)
		web.POST("/login/end", browserFlow.LoginEnd)
		web.GET("/user_info", browserFlow.UserInfo)
		web.GET("/claims", browserFlow.Claims)
		web.POST("/logout", browserFlow.Logout)
	}
	private := r.Group("/api", loggerMiddleware)
	{

		validateJWT, err := newValidateJWT(ctx, insecureTLS, oidcURL, oidcBackchannel, logger, clientIdWeb, clientIdCli, store)
		if err != nil {
			return nil, err
		}

		private.Use(validateJWT)
		private.Use(api.CreateUserIfNotExists())
		// Zones
		private.GET("/organizations", api.ListOrganizations)
		private.POST("/organizations", api.CreateOrganization)
		private.GET("/organizations/:organization", api.GetOrganizations)
		private.DELETE("/organizations/:organization", api.DeleteOrganization)
		private.GET("/organizations/:organization/devices", api.ListDevicesInOrganization)
		private.GET("/organizations/:organization/devices/:id", api.GetDeviceInOrganization)
		private.GET("/organizations/:organization/users", api.ListUsersInOrganization)
		// Invitations
		private.POST("/invitations", api.CreateInvitation)
		private.POST("/invitations/:invitation/accept", api.AcceptInvitation)
		private.DELETE("/invitations/:invitation", api.DeleteInvitation)
		// Devices
		private.GET("/devices", api.ListDevices)
		private.GET("/devices/:id", api.GetDevice)
		private.PATCH("/devices/:id", api.UpdateDevice)
		private.POST("/devices", api.CreateDevice)
		private.DELETE("/devices/:id", api.DeleteDevice)
		// Users
		private.GET("/users/:id", api.GetUser)
		private.GET("/users", api.ListUsers)
		// private.PATCH("/users/:id", api.PatchUser)
		private.DELETE("/users/:id", api.DeleteUser)
		private.DELETE("/users/:id/organizations/:organization", api.DeleteUserFromOrganization)
		// Feature Flags
		private.GET("fflags", api.ListFeatureFlags)
		private.GET("fflags/:name", api.GetFeatureFlag)
	}

	r.GET("/api/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler), loggerMiddleware)

	// Don't log the health/readiness checks.
	r.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "UP",
		})
	})
	r.GET("/live", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "UP",
		})
	})

	return r, nil
}

func newValidateJWT(ctx context.Context, insecureTLS bool, oidcURL, oidcBackchannel string, logger *zap.SugaredLogger, clientIdWeb, clientIdCli string, store storage.Store) (func(*gin.Context), error) {
	if insecureTLS {
		transport := &http.Transport{
			// #nosec -- G402: TLS InsecureSkipVerify set true.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: transport}
		ctx = oidc.ClientContext(ctx, client)
	}

	if oidcBackchannel != "" {
		ctx = oidc.InsecureIssuerURLContext(ctx,
			oidcURL,
		)
		oidcURL = oidcBackchannel
	}
	provider, err := oidc.NewProvider(ctx, oidcURL)
	if err != nil {
		return nil, err
	}

	var claims struct {
		JWKSUri string `json:"jwks_uri"`
	}
	err = provider.Claims(&claims)
	if err != nil {
		return nil, err
	}

	return ValidateJWT(ctx, logger, claims.JWKSUri, clientIdWeb, clientIdCli, store)
}

func newPrometheus() *ginprometheus.Prometheus {
	p := ginprometheus.NewPrometheus("apiserver")
	p.ReqCntURLLabelMappingFn = func(c *gin.Context) string {
		url := c.Request.URL.Path
		for _, p := range c.Params {
			if p.Key == "id" {
				url = strings.Replace(url, p.Value, ":id", 1)
				break
			}
			// If zone cardinality is too big we'll replace here too
		}
		return url
	}
	return p
}
