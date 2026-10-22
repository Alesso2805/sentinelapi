"""SentinelAPI's own Alembic history for its tables (ADR-0006)."""

# Its own version table, so these migrations share a database with the app's own.
VERSION_TABLE = "sentinel_alembic_version"
