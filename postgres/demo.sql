--
-- PostgreSQL database dump
--

-- Dumped from database version 16.0 (Debian 16.0-1.pgdg120+1)
-- Dumped by pg_dump version 16.0 (Debian 16.0-1.pgdg120+1)

SET statement_timeout
= 0;
SET lock_timeout
= 0;
SET idle_in_transaction_session_timeout
= 0;
SET client_encoding
= 'UTF8';
SET standard_conforming_strings
= on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies
= false;
SET xmloption
= content;
SET client_min_messages
= warning;
SET row_security
= off;

SET default_tablespace
= '';

SET default_table_access_method
= heap;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: ore_64_8_v1_term; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.ore_64_8_v1_term AS (
	bytes bytea
);


ALTER TYPE public.ore_64_8_v1_term OWNER TO postgres;

--
-- Name: ore_64_8_v1; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.ore_64_8_v1 AS (
	terms public.ore_64_8_v1_term[]
);


ALTER TYPE public.ore_64_8_v1 OWNER TO postgres;

--
-- Name: compare_ore_64_8_v1(public.ore_64_8_v1, public.ore_64_8_v1); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.compare_ore_64_8_v1(a public.ore_64_8_v1, b public.ore_64_8_v1) RETURNS integer
    LANGUAGE plpgsql
    AS $$
  DECLARE
    cmp_result integer;
  BEGIN
    -- Recursively compare blocks bailing as soon as we can make a decision
    RETURN compare_ore_array(a.terms, b.terms);
  END
$$;


ALTER FUNCTION public.compare_ore_64_8_v1(a public.ore_64_8_v1, b public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: compare_ore_64_8_v1_term(public.ore_64_8_v1_term, public.ore_64_8_v1_term); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.compare_ore_64_8_v1_term(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) RETURNS integer
    LANGUAGE plpgsql
    AS $$
  DECLARE
    eq boolean := true;
    unequal_block smallint := 0;
    hash_key bytea;
    target_block bytea;

    left_block_size CONSTANT smallint := 16;
    right_block_size CONSTANT smallint := 32;
    right_offset CONSTANT smallint := 136; -- 8 * 17

    indicator smallint := 0;
  BEGIN
    IF a IS NULL AND b IS NULL THEN
      RETURN 0;
    END IF;

    IF a IS NULL THEN
      RETURN -1;
    END IF;

    IF b IS NULL THEN
      RETURN 1;
    END IF;

    IF bit_length(a.bytes) != bit_length(b.bytes) THEN
      RAISE EXCEPTION 'Ciphertexts are different lengths';
    END IF;

    FOR block IN 0..7 LOOP
      -- Compare each PRP (byte from the first 8 bytes) and PRF block (8 byte
      -- chunks of the rest of the value).
      -- NOTE:
      -- * Substr is ordinally indexed (hence 1 and not 0, and 9 and not 8).
      -- * We are not worrying about timing attacks here; don't fret about
      --   the OR or !=.
      IF
        substr(a.bytes, 1 + block, 1) != substr(b.bytes, 1 + block, 1)
        OR substr(a.bytes, 9 + left_block_size * block, left_block_size) != substr(b.bytes, 9 + left_block_size * BLOCK, left_block_size)
      THEN
        -- set the first unequal block we find
        IF eq THEN
          unequal_block := block;
        END IF;
        eq = false;
      END IF;
    END LOOP;

    IF eq THEN
      RETURN 0::integer;
    END IF;

    -- Hash key is the IV from the right CT of b
    hash_key := substr(b.bytes, right_offset + 1, 16);

    -- first right block is at right offset + nonce_size (ordinally indexed)
    target_block := substr(b.bytes, right_offset + 17 + (unequal_block * right_block_size), right_block_size);

    indicator := (
      get_bit(
        encrypt(
          substr(a.bytes, 9 + (left_block_size * unequal_block), left_block_size),
          hash_key,
          'aes-ecb'
        ),
        0
      ) + get_bit(target_block, get_byte(a.bytes, unequal_block))) % 2;

    IF indicator = 1 THEN
      RETURN 1::integer;
    ELSE
      RETURN -1::integer;
    END IF;
  END;
$$;


ALTER FUNCTION public.compare_ore_64_8_v1_term(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: compare_ore_array(public.ore_64_8_v1_term[], public.ore_64_8_v1_term[]); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.compare_ore_array(a public.ore_64_8_v1_term[], b public.ore_64_8_v1_term[]) RETURNS integer
    LANGUAGE plpgsql
    AS $$
  DECLARE
    cmp_result integer;
  BEGIN
    IF (array_length(a, 1) = 0 OR a IS NULL) AND (array_length(b, 1) = 0 OR b IS NULL) THEN
      RETURN 0;
    END IF;
    IF array_length(a, 1) = 0 OR a IS NULL THEN
      RETURN -1;
    END IF;
    IF array_length(b, 1) = 0 OR a IS NULL THEN
      RETURN 1;
    END IF;

    cmp_result := compare_ore_64_8_v1_term(a[1], b[1]);
    IF cmp_result = 0 THEN
    -- Removes the first element in the array, and calls this fn again to compare the next element/s in the array.
      RETURN compare_ore_array(a[2:array_length(a,1)], b[2:array_length(b,1)]);
    END IF;

    RETURN cmp_result;
  END
$$;


ALTER FUNCTION public.compare_ore_array(a public.ore_64_8_v1_term[], b public.ore_64_8_v1_term[]) OWNER TO postgres;

--
-- Name: ore_64_8_v1_eq(public.ore_64_8_v1, public.ore_64_8_v1); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_eq(a public.ore_64_8_v1, b public.ore_64_8_v1) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1(a, b) = 0
$$;


ALTER FUNCTION public.ore_64_8_v1_eq(a public.ore_64_8_v1, b public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: ore_64_8_v1_gt(public.ore_64_8_v1, public.ore_64_8_v1); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_gt(a public.ore_64_8_v1, b public.ore_64_8_v1) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1(a, b) = 1
$$;


ALTER FUNCTION public.ore_64_8_v1_gt(a public.ore_64_8_v1, b public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: ore_64_8_v1_gte(public.ore_64_8_v1, public.ore_64_8_v1); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_gte(a public.ore_64_8_v1, b public.ore_64_8_v1) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1(a, b) != -1
$$;


ALTER FUNCTION public.ore_64_8_v1_gte(a public.ore_64_8_v1, b public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: ore_64_8_v1_lt(public.ore_64_8_v1, public.ore_64_8_v1); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_lt(a public.ore_64_8_v1, b public.ore_64_8_v1) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1(a, b) = -1
$$;


ALTER FUNCTION public.ore_64_8_v1_lt(a public.ore_64_8_v1, b public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: ore_64_8_v1_lte(public.ore_64_8_v1, public.ore_64_8_v1); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_lte(a public.ore_64_8_v1, b public.ore_64_8_v1) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1(a, b) != 1
$$;


ALTER FUNCTION public.ore_64_8_v1_lte(a public.ore_64_8_v1, b public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: ore_64_8_v1_neq(public.ore_64_8_v1, public.ore_64_8_v1); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_neq(a public.ore_64_8_v1, b public.ore_64_8_v1) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1(a, b) <> 0
$$;


ALTER FUNCTION public.ore_64_8_v1_neq(a public.ore_64_8_v1, b public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: ore_64_8_v1_term_eq(public.ore_64_8_v1_term, public.ore_64_8_v1_term); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_term_eq(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1_term(a, b) = 0
$$;


ALTER FUNCTION public.ore_64_8_v1_term_eq(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: ore_64_8_v1_term_gt(public.ore_64_8_v1_term, public.ore_64_8_v1_term); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_term_gt(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1_term(a, b) = 1
$$;


ALTER FUNCTION public.ore_64_8_v1_term_gt(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: ore_64_8_v1_term_gte(public.ore_64_8_v1_term, public.ore_64_8_v1_term); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_term_gte(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1_term(a, b) != -1
$$;


ALTER FUNCTION public.ore_64_8_v1_term_gte(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: ore_64_8_v1_term_lt(public.ore_64_8_v1_term, public.ore_64_8_v1_term); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_term_lt(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1_term(a, b) = -1
$$;


ALTER FUNCTION public.ore_64_8_v1_term_lt(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: ore_64_8_v1_term_lte(public.ore_64_8_v1_term, public.ore_64_8_v1_term); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_term_lte(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1_term(a, b) != 1
$$;


ALTER FUNCTION public.ore_64_8_v1_term_lte(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: ore_64_8_v1_term_neq(public.ore_64_8_v1_term, public.ore_64_8_v1_term); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ore_64_8_v1_term_neq(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) RETURNS boolean
    LANGUAGE sql
    AS $$
  SELECT compare_ore_64_8_v1_term(a, b) <> 0
$$;


ALTER FUNCTION public.ore_64_8_v1_term_neq(a public.ore_64_8_v1_term, b public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: <; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.< (
    FUNCTION = public.ore_64_8_v1_term_lt,
    LEFTARG = public.ore_64_8_v1_term,
    RIGHTARG = public.ore_64_8_v1_term,
    COMMUTATOR = OPERATOR(public.>),
    NEGATOR = OPERATOR(public.>=),
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);


ALTER OPERATOR public.< (public.ore_64_8_v1_term, public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: <; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.< (
    FUNCTION = public.ore_64_8_v1_lt,
    LEFTARG = public.ore_64_8_v1,
    RIGHTARG = public.ore_64_8_v1,
    COMMUTATOR = OPERATOR(public.>),
    NEGATOR = OPERATOR(public.>=),
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);


ALTER OPERATOR public.< (public.ore_64_8_v1, public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: <=; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.<= (
    FUNCTION = public.ore_64_8_v1_term_lte,
    LEFTARG = public.ore_64_8_v1_term,
    RIGHTARG = public.ore_64_8_v1_term,
    COMMUTATOR = OPERATOR(public.>=),
    NEGATOR = OPERATOR(public.>),
    RESTRICT = scalarlesel,
    JOIN = scalarlejoinsel
);


ALTER OPERATOR public.<= (public.ore_64_8_v1_term, public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: <=; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.<= (
    FUNCTION = public.ore_64_8_v1_lte,
    LEFTARG = public.ore_64_8_v1,
    RIGHTARG = public.ore_64_8_v1,
    COMMUTATOR = OPERATOR(public.>=),
    NEGATOR = OPERATOR(public.>),
    RESTRICT = scalarlesel,
    JOIN = scalarlejoinsel
);


ALTER OPERATOR public.<= (public.ore_64_8_v1, public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: <>; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.<> (
    FUNCTION = public.ore_64_8_v1_term_neq,
    LEFTARG = public.ore_64_8_v1_term,
    RIGHTARG = public.ore_64_8_v1_term,
    NEGATOR = OPERATOR(public.=),
    MERGES,
    HASHES,
    RESTRICT = eqsel,
    JOIN = eqjoinsel
);


ALTER OPERATOR public.<> (public.ore_64_8_v1_term, public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: <>; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.<> (
    FUNCTION = public.ore_64_8_v1_neq,
    LEFTARG = public.ore_64_8_v1,
    RIGHTARG = public.ore_64_8_v1,
    NEGATOR = OPERATOR(public.=),
    MERGES,
    HASHES,
    RESTRICT = eqsel,
    JOIN = eqjoinsel
);


ALTER OPERATOR public.<> (public.ore_64_8_v1, public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: =; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.= (
    FUNCTION = public.ore_64_8_v1_term_eq,
    LEFTARG = public.ore_64_8_v1_term,
    RIGHTARG = public.ore_64_8_v1_term,
    NEGATOR = OPERATOR(public.<>),
    MERGES,
    HASHES,
    RESTRICT = eqsel,
    JOIN = eqjoinsel
);


ALTER OPERATOR public.= (public.ore_64_8_v1_term, public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: =; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.= (
    FUNCTION = public.ore_64_8_v1_eq,
    LEFTARG = public.ore_64_8_v1,
    RIGHTARG = public.ore_64_8_v1,
    NEGATOR = OPERATOR(public.<>),
    MERGES,
    HASHES,
    RESTRICT = eqsel,
    JOIN = eqjoinsel
);


ALTER OPERATOR public.= (public.ore_64_8_v1, public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: >; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.> (
    FUNCTION = public.ore_64_8_v1_term_gt,
    LEFTARG = public.ore_64_8_v1_term,
    RIGHTARG = public.ore_64_8_v1_term,
    COMMUTATOR = OPERATOR(public.<),
    NEGATOR = OPERATOR(public.<=),
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);


ALTER OPERATOR public.> (public.ore_64_8_v1_term, public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: >; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.> (
    FUNCTION = public.ore_64_8_v1_gt,
    LEFTARG = public.ore_64_8_v1,
    RIGHTARG = public.ore_64_8_v1,
    COMMUTATOR = OPERATOR(public.<),
    NEGATOR = OPERATOR(public.<=),
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);


ALTER OPERATOR public.> (public.ore_64_8_v1, public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: >=; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.>= (
    FUNCTION = public.ore_64_8_v1_term_gte,
    LEFTARG = public.ore_64_8_v1_term,
    RIGHTARG = public.ore_64_8_v1_term,
    COMMUTATOR = OPERATOR(public.<=),
    NEGATOR = OPERATOR(public.<),
    RESTRICT = scalarlesel,
    JOIN = scalarlejoinsel
);


ALTER OPERATOR public.>= (public.ore_64_8_v1_term, public.ore_64_8_v1_term) OWNER TO postgres;

--
-- Name: >=; Type: OPERATOR; Schema: public; Owner: postgres
--

CREATE OPERATOR public.>= (
    FUNCTION = public.ore_64_8_v1_gte,
    LEFTARG = public.ore_64_8_v1,
    RIGHTARG = public.ore_64_8_v1,
    COMMUTATOR = OPERATOR(public.<=),
    NEGATOR = OPERATOR(public.<),
    RESTRICT = scalarlesel,
    JOIN = scalarlejoinsel
);


ALTER OPERATOR public.>= (public.ore_64_8_v1, public.ore_64_8_v1) OWNER TO postgres;

--
-- Name: ore_64_8_v1_btree_ops; Type: OPERATOR FAMILY; Schema: public; Owner: postgres
--

CREATE OPERATOR FAMILY public.ore_64_8_v1_btree_ops USING btree;


ALTER OPERATOR FAMILY public.ore_64_8_v1_btree_ops USING btree OWNER TO postgres;

--
-- Name: ore_64_8_v1_btree_ops; Type: OPERATOR CLASS; Schema: public; Owner: postgres
--

CREATE OPERATOR CLASS public.ore_64_8_v1_btree_ops
    DEFAULT FOR TYPE public.ore_64_8_v1 USING btree FAMILY public.ore_64_8_v1_btree_ops AS
    OPERATOR 1 public.<(public.ore_64_8_v1,public.ore_64_8_v1) ,
    OPERATOR 2 public.<=(public.ore_64_8_v1,public.ore_64_8_v1) ,
    OPERATOR 3 public.=(public.ore_64_8_v1,public.ore_64_8_v1) ,
    OPERATOR 4 public.>=(public.ore_64_8_v1,public.ore_64_8_v1) ,
    OPERATOR 5 public.>(public.ore_64_8_v1,public.ore_64_8_v1) ,
    FUNCTION 1 (public.ore_64_8_v1, public.ore_64_8_v1) public.compare_ore_64_8_v1(public.ore_64_8_v1,public.ore_64_8_v1);


ALTER OPERATOR CLASS public.ore_64_8_v1_btree_ops USING btree OWNER TO postgres;

--
-- Name: ore_64_8_v1_term_btree_ops; Type: OPERATOR FAMILY; Schema: public; Owner: postgres
--

CREATE OPERATOR FAMILY public.ore_64_8_v1_term_btree_ops USING btree;


ALTER OPERATOR FAMILY public.ore_64_8_v1_term_btree_ops USING btree OWNER TO postgres;

--
-- Name: ore_64_8_v1_term_btree_ops; Type: OPERATOR CLASS; Schema: public; Owner: postgres
--

CREATE OPERATOR CLASS public.ore_64_8_v1_term_btree_ops
    DEFAULT FOR TYPE public.ore_64_8_v1_term USING btree FAMILY public.ore_64_8_v1_term_btree_ops AS
    OPERATOR 1 public.<(public.ore_64_8_v1_term,public.ore_64_8_v1_term) ,
    OPERATOR 2 public.<=(public.ore_64_8_v1_term,public.ore_64_8_v1_term) ,
    OPERATOR 3 public.=(public.ore_64_8_v1_term,public.ore_64_8_v1_term) ,
    OPERATOR 4 public.>=(public.ore_64_8_v1_term,public.ore_64_8_v1_term) ,
    OPERATOR 5 public.>(public.ore_64_8_v1_term,public.ore_64_8_v1_term) ,
    FUNCTION 1 (public.ore_64_8_v1_term, public.ore_64_8_v1_term) public.compare_ore_64_8_v1_term(public.ore_64_8_v1_term,public.ore_64_8_v1_term);


ALTER OPERATOR CLASS public.ore_64_8_v1_term_btree_ops USING btree OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users
(
    id integer NOT NULL,
    name character varying(30),
    email character varying(30),
    __name_encrypted text,
    __name_ore public.ore_64_8_v1,
    __name_match integer[],
    __name_unique text,
    __email_encrypted text,
    __email_ore public.ore_64_8_v1,
    __email_match integer[],
    __email_unique text
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users
(id, name, email) FROM stdin;
1	Anakin	anakin@skywalker.com
2	Luke	luke@skywalker.com
\.


--
-- PostgreSQL database dump complete
--
