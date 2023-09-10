package ds

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	parseConfig   = pgxpool.ParseConfig   // Placeholder for pgxpool.ParseConfig
	newWithConfig = pgxpool.NewWithConfig // Placeholder for pgxpool.NewWithConfig

	eexec           = executor.exec        // Placeholder for executor.exec
	eexecConnection = (*pgxpool.Conn).Exec // Placeholder for (*pgxpool.Conn).Exec
	ecommit         = executor.commit      // Placeholder for executor.commit
	erollback       = executor.rollback    // Placeholder for executor.rollback

	usersTableMigrate         = migrateUser          // Placeholder for migrateUser
	sessionsTableMigrate      = migrateSession       // Placeholder for migrateSession
	loginAttemptsTableMigrate = migrateLoginAttempts // Placeholder for migrateLoginAttempts
	restoreCodesTableMigrate  = migrateRestoreCodes  // Placeholder for migrateRestoreCodes

	getTransaction = (*DataStorageUsers).GetTransaction // Placeholder for migrateRestoreCodes
)

// DataStorageUsers holds pool for connections to control user data storage.
type DataStorageUsers struct {
	// pool is the connection pool to manage pgsql connections.
	// I've decided to use ready-to-use pool, because implementing own
	// would be waste of time.
	pool *pgxpool.Pool
}

// Connect inits connecton(s) with database.
func (ds *DataStorageUsers) Connect(ctx context.Context, dsn string) error {
	connConfig, err := parseConfig(dsn)
	if err != nil {
		return fmt.Errorf("[DS CONNECT] %w", err)
	}

	pool, err := newWithConfig(ctx, connConfig)
	if err != nil {
		return fmt.Errorf("[DS CONNECT] %w", err)
	}

	time.Sleep(time.Second * 1) // Temp fix for slow env

	err = pool.Ping(ctx)
	if err != nil {
		return fmt.Errorf("[DS CONNECT] ping: %w", err)
	}

	ds.pool = pool

	return nil
}

// Close closes all connections. It will be blocked until all ops are done
// and connections returned to pool.
func (ds *DataStorageUsers) Close() error {
	ds.pool.Close()

	return nil
}

// GetTransaction acquires connection from prool and starts transaction.
// Returned executor interface.
func (ds *DataStorageUsers) GetTransaction(ctx context.Context) (executor, error) {
	tx, err := ds.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("[DS][CreateUser]: %w", err)
	}

	return &transaction{tx: tx, ctx: ctx}, nil
}

// Transaction works with transactions from pool, implementing executor interface.
type transaction struct {
	tx  pgx.Tx
	ctx context.Context
}

// exec executes SQL code
func (t *transaction) exec(sql string, arguments ...any) error {
	_, err := t.tx.Exec(
		t.ctx,
		sql,
		arguments...,
	)

	return err
}

// rollback reverts changes in transaction
func (t *transaction) rollback() error {
	return t.tx.Rollback(t.ctx)
}

// commit finishes transaction
func (t *transaction) commit() error {
	return t.tx.Commit(t.ctx)
}

// Executor interface to work with transactions. It's intended to work with DataStorageUsers methods.
type executor interface {
	// exec executes SQL code
	exec(sql string, arguments ...any) error

	// rollback reverts changes in transaction
	rollback() error

	// commit finishes transaction
	commit() error
}
