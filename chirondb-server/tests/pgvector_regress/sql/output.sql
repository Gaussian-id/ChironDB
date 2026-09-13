-- pgvector regress subset: text-format DataRow output for SELECT.

CREATE TABLE oot (id INTEGER PRIMARY KEY, embedding vector(2));
INSERT INTO oot (id, embedding) VALUES (1, '[1, 0]'::vector);
INSERT INTO oot (id, embedding) VALUES (2, '[0, 1]'::vector);
-- search returns 2 rows in distance order
SELECT id, embedding <-> '[1, 0]'::vector AS d FROM oot ORDER BY embedding <-> '[1, 0]'::vector LIMIT 2;
DROP TABLE oot;
