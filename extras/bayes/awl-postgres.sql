CREATE TABLE awl (
    username character varying(100) DEFAULT ''::character varying NOT NULL,
    email character varying(255) DEFAULT ''::character varying NOT NULL,
    ip character varying(40) DEFAULT ''::character varying NOT NULL,
    count bigint DEFAULT 0::bigint NOT NULL,
    totscore double precision DEFAULT 0::double precision NOT NULL,
    signedby character varying(255) DEFAULT ''::character varying NOT NULL
);