package ds

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func (ds *DataStorageUsers) Migrate(ctx context.Context) error {
	// Migrating manually, no ORM or anything.
	// I was thinking to use reflect + struct tags in models + something like github.com/huandu/go-sqlbuilder
	// to make Migrate() flexible and avoid ORM
	// (getStructSQLParameters in Readme.md would work to get data from reflected fields).
	// But then i thought that it's way too complicated for this test service (takes a lot to oversee and mitigate).
	// So i'm leaving here just simple plaintext SQL code like some barbarian. Sorry.

	conn, err := ds.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("[DS][MIGRATE]: %w", err)
	}
	defer conn.Release()

	// User data
	err = usersTableMigrate(conn, ctx)
	if err != nil {
		return fmt.Errorf("[DS][MIGRATE]%w", err)
	}

	// Session data
	err = sessionsTableMigrate(conn, ctx)
	if err != nil {
		return fmt.Errorf("[DS][MIGRATE]%w", err)
	}

	// Failed login attempts
	err = loginAttemptsTableMigrate(conn, ctx)
	if err != nil {
		return fmt.Errorf("[DS][MIGRATE]%w", err)
	}

	// Password restore codes
	err = restoreCodesTableMigrate(conn, ctx)
	if err != nil {
		return fmt.Errorf("[DS][MIGRATE]%w", err)
	}

	return nil
}

// migrateUser creates user_data table and indexes, relations
func migrateUser(conn *pgxpool.Conn, ctx context.Context) error {
	_, err := eexecConnection(
		conn,
		ctx,
		`CREATE TABLE IF NOT EXISTS "user_data"
		(
			"user_id" text,
			"login" text NOT NULL,
			"password_hash" text NOT NULL,
			"first_name" text NOT NULL,
			"last_name" text NOT NULL,
			"email" text NOT NULL,
			"created_at" timestamptz DEFAULT CURRENT_TIMESTAMP,
			"blocked_login" boolean NOT NULL DEFAULT false,
			"blocked_at" timestamptz,
			"must_change_password" boolean NOT NULL DEFAULT false,PRIMARY KEY ("user_id")
		);
		
		CREATE UNIQUE INDEX IF NOT EXISTS "idx_usrlogin" 
		ON "user_data" ("login");
		
		CREATE UNIQUE INDEX IF NOT EXISTS "idx_usremail" 
		ON "user_data" ("email")`,
	)
	if err != nil {
		return fmt.Errorf("[USER] %w: %w", ErrMigratingTable, err)
	}

	return nil
}

// migrateSession creates user_sessions table and indexes, relations
func migrateSession(conn *pgxpool.Conn, ctx context.Context) error {
	_, err := eexecConnection(
		conn,
		ctx,
		`CREATE TABLE IF NOT EXISTS "user_sessions" 
		(
			"session_id" text,
			"user_id" text NOT NULL,
			"created_at" timestamptz DEFAULT CURRENT_TIMESTAMP,
			"closed_at" timestamptz,
			PRIMARY KEY ("session_id")
		);
		
		CREATE INDEX IF NOT EXISTS "idx_sessuid" 
		ON "user_sessions" ("user_id");
		
		ALTER TABLE user_sessions 
		DROP CONSTRAINT IF EXISTS user_sessions_fk;
		
		ALTER TABLE user_sessions 
		ADD CONSTRAINT user_sessions_fk FOREIGN KEY (user_id) 
		REFERENCES user_data(user_id) ON DELETE CASCADE ON UPDATE CASCADE;
		`,
	)
	if err != nil {
		return fmt.Errorf("[SESSION] %w: %w", ErrMigratingTable, err)
	}

	return nil
}

// migrateLoginAttempts creates user_failed_login_attempts table and indexes, relations
func migrateLoginAttempts(conn *pgxpool.Conn, ctx context.Context) error {
	_, err := eexecConnection(
		conn,
		ctx,
		`CREATE TABLE IF NOT EXISTS "user_failed_login_attempts" 
		(
			"attempt_id" bigserial,
			"user_id" text NOT NULL,
			"created_at" timestamptz DEFAULT CURRENT_TIMESTAMP,
			"ip_addr" text NOT NULL,PRIMARY KEY ("attempt_id")
		);
		
		CREATE INDEX IF NOT EXISTS "idx_faaddr" 
		ON "user_failed_login_attempts" ("ip_addr");

		CREATE INDEX IF NOT EXISTS "idx_fauid" 
		ON "user_failed_login_attempts" ("user_id");

		ALTER TABLE user_failed_login_attempts 
		DROP CONSTRAINT IF EXISTS user_failed_login_attempts_fk; 
		
		ALTER TABLE user_failed_login_attempts 
		ADD CONSTRAINT user_failed_login_attempts_fk FOREIGN KEY (user_id) 
		REFERENCES user_data(user_id) ON DELETE CASCADE ON UPDATE CASCADE;`,
	)
	if err != nil {
		return fmt.Errorf("[LOGIN ATTEMPTS] %w: %w", ErrMigratingTable, err)
	}

	return nil
}

// migrateRestoreCodes creates user_password_restore_codes table and indexes, relations
func migrateRestoreCodes(conn *pgxpool.Conn, ctx context.Context) error {
	_, err := eexecConnection(
		conn,
		ctx,
		`CREATE TABLE IF NOT EXISTS "user_password_restore_codes" 
		(
			"code_id" bigserial,
			"user_id" text NOT NULL,
			"code" text NOT NULL,
			"created_at" timestamptz DEFAULT CURRENT_TIMESTAMP,
			"valid_until" timestamptz,
			"used_at" timestamptz,
			PRIMARY KEY ("code_id")
		);
		
		CREATE UNIQUE INDEX IF NOT EXISTS "idx_restcode" 
		ON "user_password_restore_codes" ("user_id","code");
		
		ALTER TABLE user_password_restore_codes 
		DROP CONSTRAINT IF EXISTS user_password_restore_codes_fk; 
		
		ALTER TABLE user_password_restore_codes 
		ADD CONSTRAINT user_password_restore_codes_fk FOREIGN KEY (user_id) 
		REFERENCES user_data(user_id) ON DELETE CASCADE ON UPDATE CASCADE;`,
	)
	if err != nil {
		return fmt.Errorf("[RESTORE CODES] %w : %w", ErrMigratingTable, err)
	}

	return nil
}
