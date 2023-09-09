package cfg

type Config struct {
	UserDatabaseDSN string `arg:"--udsn, env:UDB" help:"Database full connection string (postgres://username:password@localhost:5432/database_name)"`
	MigrateDatabase bool   `arg:"-m, env:MIGRATE" help:"Migrate database on start"`

	HTTPListenAt string `arg:"-h, env:HTTP_LISTEN_AT" default:"localhost:8080"`
	GRPCListenAt string `arg:"-g, env:GRPC_LISTEN_AT" default:"localhost:9090"`
	JWTSecret    string `arg:"-s, env:JWTSECRET, required"`
}
