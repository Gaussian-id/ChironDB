-- pgvector regress subset: vector(N) type basics.
-- Statements must succeed unless prefixed with `-- expect: <SQLSTATE>`.

CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE vt (id INTEGER PRIMARY KEY, embedding vector(3));
INSERT INTO vt (id, embedding) VALUES (1, '[1, 2, 3]'::vector);
INSERT INTO vt (id, embedding) VALUES (2, '[-1.5, 0, 2]'::vector);
-- expect: 22023
INSERT INTO vt (id, embedding) VALUES (3, '[1, 2, NaN]'::vector);
DROP TABLE vt;
