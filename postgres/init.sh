#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE DATABASE stash;
	GRANT ALL PRIVILEGES ON DATABASE stash TO postgres;
EOSQL

psql -f demo.sql -U postgres stash