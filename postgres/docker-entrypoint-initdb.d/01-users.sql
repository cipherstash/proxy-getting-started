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

COPY public.users
(id, name, email) FROM stdin;
1	Anakin	anakin@skywalker.com
2	Luke	luke@skywalker.com
\.
