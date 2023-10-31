package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
	"github.com/nexodus-io/nexodus/internal/handlers/fetchmgr"
	"github.com/nexodus-io/nexodus/internal/handlers/fetchmgr/envfm"
	"github.com/nexodus-io/nexodus/internal/models"
	"github.com/nexodus-io/nexodus/internal/signalbus"
	"github.com/redis/go-redis/v9"
	"net/http"
	"strconv"

	"github.com/nexodus-io/nexodus/internal/database"
	"github.com/open-policy-agent/opa/storage"

	"github.com/nexodus-io/nexodus/internal/util"

	"github.com/google/uuid"
	"github.com/nexodus-io/nexodus/internal/fflags"
	"github.com/nexodus-io/nexodus/internal/ipam"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var tracer trace.Tracer

func init() {
	tracer = otel.Tracer("github.com/nexodus-io/nexodus/internal/handlers")
}

type API struct {
	logger         *zap.SugaredLogger
	db             *gorm.DB
	ipam           ipam.IPAM
	defaultZoneID  uuid.UUID
	fflags         *fflags.FFlags
	transaction    database.TransactionFunc
	dialect        database.Dialect
	store          storage.Store
	signalBus      signalbus.SignalBus
	redis          *redis.Client
	sessionManager *session.Manager
	fetchManager   fetchmgr.FetchManager
	onlineTracker  *DeviceTracker
	URL            string
	PrivateKey     *rsa.PrivateKey
	Certificates   []*x509.Certificate
}

func NewAPI(
	parent context.Context,
	logger *zap.SugaredLogger,
	db *gorm.DB,
	ipam ipam.IPAM,
	fflags *fflags.FFlags,
	store storage.Store,
	signalBus signalbus.SignalBus,
	redis *redis.Client,
	sessionManager *session.Manager,
) (*API, error) {

	ctx, span := tracer.Start(parent, "NewAPI")
	defer span.End()

	transactionFunc, dialect, err := database.GetTransactionFunc(db)
	if err != nil {
		return nil, err
	}

	fetchManager, err := envfm.New(logger.Desugar())
	if err != nil {
		return nil, err
	}

	onlineTracker, err := New(logger.Desugar())
	if err != nil {
		return nil, err
	}

	api := &API{
		logger:         logger,
		db:             db,
		ipam:           ipam,
		defaultZoneID:  uuid.Nil,
		fflags:         fflags,
		transaction:    transactionFunc,
		dialect:        dialect,
		store:          store,
		signalBus:      signalBus,
		redis:          redis,
		sessionManager: sessionManager,
		fetchManager:   fetchManager,
		onlineTracker:  onlineTracker,
	}

	if err := api.populateStore(ctx); err != nil {
		return nil, err
	}

	return api, nil
}

func (api *API) Logger(ctx context.Context) *zap.SugaredLogger {
	return util.WithTrace(ctx, api.logger)
}

func (api *API) sendList(c *gin.Context, ctx context.Context, getList func(db *gorm.DB) (fetchmgr.ResourceList, error)) {
	db := api.db.WithContext(ctx)

	items, err := getList(db)
	if err != nil {
		api.sendInternalServerError(c, err)
		return
	}

	// For pagination
	c.Header("Access-Control-Expose-Headers", TotalCountHeader)
	c.Header(TotalCountHeader, strconv.Itoa(items.Len()))
	c.JSON(http.StatusOK, items)
}

func (api *API) sendInternalServerError(c *gin.Context, err error) {
	SendInternalServerError(c, api.logger, err)
}

func SendInternalServerError(c *gin.Context, logger *zap.SugaredLogger, err error) {
	ctx := c.Request.Context()
	util.WithTrace(ctx, logger).Errorw("internal server error", "error", err)

	result := models.InternalServerError{
		BaseError: models.BaseError{
			Error: "internal server error",
		},
	}
	sc := trace.SpanFromContext(ctx).SpanContext()
	if sc.HasTraceID() {
		result.TraceId = sc.TraceID().String()
	}
	c.JSON(http.StatusInternalServerError, result)
}
