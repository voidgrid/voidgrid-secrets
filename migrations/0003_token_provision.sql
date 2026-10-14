-- A provisioning token may list and create secrets over the API (create
-- only: it can't reveal, update, rename, delete or grant). It is for
-- scripts that load keys into the store, and the account still assigns
-- them to tokens.
ALTER TABLE machine_tokens ADD COLUMN provision INTEGER NOT NULL DEFAULT 0;
