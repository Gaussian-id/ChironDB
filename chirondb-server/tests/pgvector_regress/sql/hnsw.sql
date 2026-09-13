-- GaussDB subset: LS-VEC is automatic; HNSW index DDL rejects, query remains live.

CREATE TABLE hn (id INTEGER PRIMARY KEY, embedding vector(4));
-- expect: 0A000
CREATE INDEX hn_idx ON hn USING hnsw (embedding vector_l2_ops);
INSERT INTO hn (id, embedding) VALUES (1, '[1, 0, 0, 0]'::vector);
INSERT INTO hn (id, embedding) VALUES (2, '[0, 1, 0, 0]'::vector);
INSERT INTO hn (id, embedding) VALUES (3, '[0, 0, 1, 0]'::vector);
SELECT id FROM hn ORDER BY embedding <-> '[1, 0, 0, 0]'::vector LIMIT 1;
-- expect: 0A000
CREATE INDEX hn_ivf ON hn USING ivfflat (embedding vector_l2_ops);
DROP TABLE hn;
