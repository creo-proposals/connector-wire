-- The site side of a connection: the tables this package's `/postgres` entry uses. Apply once, in a
-- transaction, with the site's own migrations. Nothing is written here until the site is paired.

-- One-use numbers. The unique key means two instances can never both accept one number.
-- Keep rows at least 601 seconds (the contract); forgetExpired deletes them after 661.
CREATE TABLE wire_nonces (
  pairing TEXT NOT NULL,
  key_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (pairing, key_id, nonce)
);

CREATE INDEX wire_nonces_seen_at_idx ON wire_nonces (seen_at);

-- A write's answer, kept under its pairing and retry key for 24 hours. The same key and body gets
-- the stored answer and acts nothing; the same key with another body is `conflict`. `answer` holds
-- {"status": <http status>, "body": <the answer body>}.
CREATE TABLE wire_answers (
  pairing TEXT NOT NULL,
  retry_key TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  op TEXT NOT NULL,
  answer JSONB,
  at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (pairing, retry_key)
);

CREATE INDEX wire_answers_at_idx ON wire_answers (at);

-- Events waiting to go to the board. A row is written in the same transaction as the thing it
-- reports. `pairing` is the pairing the event was queued for: the sender sends only the current
-- pairing's rows, so a site that is paired again never signs an earlier pairing's events for the
-- new one; they stay, unsent. `next_at` is when the sender may try it again.
CREATE TABLE wire_outbox (
  id TEXT PRIMARY KEY,
  pairing TEXT NOT NULL,
  kind TEXT NOT NULL,
  at TIMESTAMPTZ NOT NULL DEFAULT now(),
  fields JSONB NOT NULL,
  sent_at TIMESTAMPTZ,
  tries INTEGER NOT NULL DEFAULT 0,
  next_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  dead BOOLEAN NOT NULL DEFAULT false,
  CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$'),
  CHECK (pairing ~ '^[A-Za-z0-9._-]{1,64}$')
);

CREATE INDEX wire_outbox_due_idx ON wire_outbox (pairing, next_at) WHERE sent_at IS NULL AND NOT dead;
CREATE INDEX wire_outbox_sent_idx ON wire_outbox (sent_at) WHERE sent_at IS NOT NULL;

-- Every change the board makes, written in the same transaction as the change. Reads are not
-- logged. Rows are never changed or removed: the triggers refuse UPDATE, DELETE and TRUNCATE.
-- Ending that is the site owner's decision, by a deliberate migration of the site's own.
CREATE TABLE wire_log (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at TIMESTAMPTZ NOT NULL DEFAULT now(),
  pairing TEXT NOT NULL,
  key_id TEXT NOT NULL,
  retry_key TEXT NOT NULL,
  op TEXT NOT NULL,
  changed BOOLEAN NOT NULL,
  before JSONB,
  after JSONB
);

CREATE INDEX wire_log_retry_key_idx ON wire_log (retry_key);

CREATE FUNCTION wire_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'wire_log is append-only: % is refused', TG_OP;
END;
$$;

CREATE TRIGGER wire_log_no_update_no_delete
  BEFORE UPDATE OR DELETE ON wire_log
  FOR EACH ROW EXECUTE FUNCTION wire_log_append_only();

CREATE TRIGGER wire_log_no_truncate
  BEFORE TRUNCATE ON wire_log
  FOR EACH STATEMENT EXECUTE FUNCTION wire_log_append_only();
