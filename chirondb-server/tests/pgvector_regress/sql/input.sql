-- pgvector regress subset: '[…]'::vector literal parsing.

CREATE TABLE inp (id INTEGER PRIMARY KEY, embedding vector(2));
INSERT INTO inp (id, embedding) VALUES (1, '[0, 0]'::vector);
INSERT INTO inp (id, embedding) VALUES (2, '[1.5, -0.5]'::vector);
INSERT INTO inp (id, embedding) VALUES (3, '[ 0.25 , 0.75 ]'::vector);
-- expect: 22023
INSERT INTO inp (id, embedding) VALUES (4, '[Inf, 0]'::vector);
DROP TABLE inp;
