CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS controllers (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL,
    endpoint text NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS signals (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    controller_id bigint NOT NULL REFERENCES controllers (id),
    namespace integer NOT NULL,
    identifier text NOT NULL,
    name text NOT NULL,
    UNIQUE (controller_id, namespace, identifier)
);

CREATE TABLE IF NOT EXISTS samples (
    time timestamptz NOT NULL,
    signal_id bigint NOT NULL,
    value_num double precision,
    value_text text,
    status text
);

SELECT create_hypertable('samples', 'time', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS samples_signal_time_idx ON samples (signal_id, time DESC);

CREATE TABLE IF NOT EXISTS latest (
    signal_id bigint PRIMARY KEY REFERENCES signals (id),
    time timestamptz NOT NULL,
    value_num double precision,
    value_text text,
    status text
);
