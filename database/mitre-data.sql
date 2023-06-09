toc.dat                                                                                             0000600 0004000 0002000 00000075527 14362250175 0014464 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        PGDMP                            {            vsocmitreintegrationdatabase    14.4    14.4 a    l           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false         m           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false         n           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false         o           1262    16639    vsocmitreintegrationdatabase    DATABASE     q   CREATE DATABASE vsocmitreintegrationdatabase WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'en_US.UTF-8';
 ,   DROP DATABASE vsocmitreintegrationdatabase;
             	   mirmaster    false         p           0    0 %   DATABASE vsocmitreintegrationdatabase    ACL     K   GRANT CONNECT ON DATABASE vsocmitreintegrationdatabase TO mirlambdareader;
                	   mirmaster    false    4463         q           0    0    SCHEMA public    ACL     �   REVOKE ALL ON SCHEMA public FROM rdsadmin;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO mirmaster;
GRANT ALL ON SCHEMA public TO PUBLIC;
GRANT USAGE ON SCHEMA public TO mirlambdareader;
                	   mirmaster    false    5                     3079    16640    aws_commons 	   EXTENSION     ?   CREATE EXTENSION IF NOT EXISTS aws_commons WITH SCHEMA public;
    DROP EXTENSION aws_commons;
                   false         r           0    0    EXTENSION aws_commons    COMMENT     M   COMMENT ON EXTENSION aws_commons IS 'Common data types across AWS services';
                        false    2                     3079    16654    aws_s3 	   EXTENSION     :   CREATE EXTENSION IF NOT EXISTS aws_s3 WITH SCHEMA public;
    DROP EXTENSION aws_s3;
                   false    2         s           0    0    EXTENSION aws_s3    COMMENT     N   COMMENT ON EXTENSION aws_s3 IS 'AWS S3 extension for importing data from S3';
                        false    3         t           0    0 �   FUNCTION query_export_to_s3(query text, s3_info aws_commons._s3_uri_1, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint)    ACL     �  REVOKE ALL ON FUNCTION aws_s3.query_export_to_s3(query text, s3_info aws_commons._s3_uri_1, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.query_export_to_s3(query text, s3_info aws_commons._s3_uri_1, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) TO rds_superuser;
          aws_s3          rds_superuser    false    257         u           0    0 �   FUNCTION query_export_to_s3(query text, bucket text, file_path text, region text, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint)    ACL     �  REVOKE ALL ON FUNCTION aws_s3.query_export_to_s3(query text, bucket text, file_path text, region text, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.query_export_to_s3(query text, bucket text, file_path text, region text, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) TO rds_superuser;
          aws_s3          rds_superuser    false    258         v           0    0 �   FUNCTION table_import_from_s3(table_name text, column_list text, options text, s3_info aws_commons._s3_uri_1, credentials aws_commons._aws_credentials_1)    ACL     ~  REVOKE ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, s3_info aws_commons._s3_uri_1, credentials aws_commons._aws_credentials_1) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, s3_info aws_commons._s3_uri_1, credentials aws_commons._aws_credentials_1) TO rds_superuser;
          aws_s3          rds_superuser    false    256         w           0    0 �   FUNCTION table_import_from_s3(table_name text, column_list text, options text, bucket text, file_path text, region text, access_key text, secret_key text, session_token text)    ACL     �  REVOKE ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, bucket text, file_path text, region text, access_key text, secret_key text, session_token text) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, bucket text, file_path text, region text, access_key text, secret_key text, session_token text) TO rds_superuser;
          aws_s3          rds_superuser    false    255                    1255    32809    updater_loop()    FUNCTION     8  CREATE FUNCTION public.updater_loop() RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
  i RECORD;
BEGIN
  --FOR i IN (SELECT ROW_NUMBER() OVER(ORDER BY (SELECT 0)) RowId,* FROM aws_base)
  FOR i IN (
    SELECT ROW_NUMBER() OVER(ORDER BY (SELECT 0)) AS RowId,
    SUBSTRING(ttp_description,1,LENGTH(ttp_description)-1) AS ttp_description,
    ttp_id
    FROM mitre_ttp_base
    )
  LOOP
    UPDATE mitre_ttp_base
    SET
        ttp_description = i.ttp_description,
        ttp_description_eng = i.ttp_description
    WHERE ttp_id = i.ttp_id;
  END LOOP;
END;
$$;
 %   DROP FUNCTION public.updater_loop();
       public       	   mirmaster    false         �            1259    16660    aws_base    TABLE       CREATE TABLE public.aws_base (
    event_rule character varying(110) NOT NULL,
    service character varying(25) NOT NULL,
    m_type character varying(10),
    m_details_esp character varying(350) NOT NULL,
    m_details_eng character varying(350) NOT NULL
);
    DROP TABLE public.aws_base;
       public         heap 	   mirmaster    false         x           0    0    TABLE aws_base    ACL     :   GRANT SELECT ON TABLE public.aws_base TO mirlambdareader;
          public       	   mirmaster    false    216         �            1259    16665    c5_base    TABLE     l   CREATE TABLE public.c5_base (
    c5_id character varying(10) NOT NULL,
    title character varying(170)
);
    DROP TABLE public.c5_base;
       public         heap 	   mirmaster    false         �            1259    16668    cis_base    TABLE     n   CREATE TABLE public.cis_base (
    cis_id character varying(10) NOT NULL,
    title character varying(170)
);
    DROP TABLE public.cis_base;
       public         heap 	   mirmaster    false         �            1259    16671    cis_nist_dir    TABLE     |   CREATE TABLE public.cis_nist_dir (
    cis_id character varying(10) NOT NULL,
    nist_id character varying(10) NOT NULL
);
     DROP TABLE public.cis_nist_dir;
       public         heap 	   mirmaster    false         �            1259    16674    cis_pci_dir    TABLE     z   CREATE TABLE public.cis_pci_dir (
    cis_id character varying(10) NOT NULL,
    pci_id character varying(10) NOT NULL
);
    DROP TABLE public.cis_pci_dir;
       public         heap 	   mirmaster    false         �            1259    16677    ens_base    TABLE     m   CREATE TABLE public.ens_base (
    ens_id character varying(10) NOT NULL,
    title character varying(80)
);
    DROP TABLE public.ens_base;
       public         heap 	   mirmaster    false         �            1259    16683    mitre_aws_dir    TABLE     �   CREATE TABLE public.mitre_aws_dir (
    ttp_id character varying(50) NOT NULL,
    service character varying(50) NOT NULL,
    event_rule character varying(150) NOT NULL
);
 !   DROP TABLE public.mitre_aws_dir;
       public         heap 	   mirmaster    false         �            1259    16686    mitre_ttp_base    TABLE     D  CREATE TABLE public.mitre_ttp_base (
    ttp_id character varying(20) NOT NULL,
    url character varying(60),
    mitigation_basic character varying(150),
    ttp_esp character varying(80),
    ttp_eng character varying(80),
    ttp_description_esp character varying(200),
    ttp_description_eng character varying(200)
);
 "   DROP TABLE public.mitre_ttp_base;
       public         heap 	   mirmaster    false         �            1259    49163    mitre_aws_view    VIEW     �  CREATE VIEW public.mitre_aws_view AS
 SELECT mb_ad.ttp_id,
    mb_ad.ttp_esp,
    mb_ad.ttp_eng,
    aws_base.m_type,
    aws_base.service,
    aws_base.event_rule,
    aws_base.m_details_esp,
    aws_base.m_details_eng
   FROM (public.aws_base
     JOIN ( SELECT mitre_ttp_base.ttp_id,
            mitre_ttp_base.ttp_esp,
            mitre_ttp_base.ttp_eng,
            mitre_aws_dir.service,
            mitre_aws_dir.event_rule
           FROM (public.mitre_aws_dir
             JOIN public.mitre_ttp_base ON (((mitre_ttp_base.ttp_id)::text = (mitre_aws_dir.ttp_id)::text)))) mb_ad ON ((((aws_base.service)::text = (mb_ad.service)::text) AND ((aws_base.event_rule)::text = (mb_ad.event_rule)::text))));
 !   DROP VIEW public.mitre_aws_view;
       public       	   mirmaster    false    222    222    216    222    216    223    223    223    216    216    216         y           0    0    TABLE mitre_aws_view    ACL     @   GRANT SELECT ON TABLE public.mitre_aws_view TO mirlambdareader;
          public       	   mirmaster    false    239         �            1259    16696 	   mitre_dir    TABLE     w   CREATE TABLE public.mitre_dir (
    ta_id character varying(10) NOT NULL,
    ttp_id character varying(20) NOT NULL
);
    DROP TABLE public.mitre_dir;
       public         heap 	   mirmaster    false         �            1259    16699    mitre_ta_base    TABLE       CREATE TABLE public.mitre_ta_base (
    ta_id character varying(10) NOT NULL,
    url character varying(60),
    ta_esp character varying(50),
    ta_eng character varying(50),
    ta_description_esp character varying(200),
    ta_description_eng character varying(200)
);
 !   DROP TABLE public.mitre_ta_base;
       public         heap 	   mirmaster    false         z           0    0    TABLE mitre_ta_base    ACL     ?   GRANT SELECT ON TABLE public.mitre_ta_base TO mirlambdareader;
          public       	   mirmaster    false    225         �            1259    49168    mitre_base_view    VIEW       CREATE VIEW public.mitre_base_view AS
 SELECT mitre_ta.ta_id,
    mitre_ta.ta_esp,
    mitre_ta.ta_eng,
    mitre_ta.ttp_id,
    mitre_ttp_base.ttp_esp,
    mitre_ttp_base.ttp_eng,
    mitre_ttp_base.url,
    mitre_ttp_base.ttp_description_esp AS description_esp,
    mitre_ttp_base.ttp_description_eng AS description_eng,
    mitre_ttp_base.mitigation_basic
   FROM (public.mitre_ttp_base
     JOIN ( SELECT mitre_ta_base.ta_id,
            mitre_ta_base.ta_esp,
            mitre_ta_base.ta_eng,
            mitre_dir.ttp_id
           FROM (public.mitre_dir
             JOIN public.mitre_ta_base ON (((mitre_dir.ta_id)::text = (mitre_ta_base.ta_id)::text)))) mitre_ta ON (((mitre_ta.ttp_id)::text = (mitre_ttp_base.ttp_id)::text)))
  ORDER BY mitre_ta.ta_id, mitre_ta.ttp_id;
 "   DROP VIEW public.mitre_base_view;
       public       	   mirmaster    false    225    223    223    223    223    223    223    223    225    225    224    224         {           0    0    TABLE mitre_base_view    ACL     A   GRANT SELECT ON TABLE public.mitre_base_view TO mirlambdareader;
          public       	   mirmaster    false    240         �            1259    16707    mitre_c5_dir    TABLE     z   CREATE TABLE public.mitre_c5_dir (
    ttp_id character varying(50) NOT NULL,
    c5_id character varying(10) NOT NULL
);
     DROP TABLE public.mitre_c5_dir;
       public         heap 	   mirmaster    false         �            1259    16710    mitre_c5_view    VIEW       CREATE VIEW public.mitre_c5_view AS
 SELECT mitre_c5_dir.ttp_id,
    c5_base.c5_id,
    c5_base.title
   FROM (public.c5_base
     JOIN public.mitre_c5_dir ON (((mitre_c5_dir.c5_id)::text = (c5_base.c5_id)::text)))
  ORDER BY mitre_c5_dir.ttp_id, c5_base.c5_id;
     DROP VIEW public.mitre_c5_view;
       public       	   mirmaster    false    226    217    226    217         |           0    0    TABLE mitre_c5_view    ACL     ?   GRANT SELECT ON TABLE public.mitre_c5_view TO mirlambdareader;
          public       	   mirmaster    false    227         �            1259    16714    mitre_cis_dir    TABLE     |   CREATE TABLE public.mitre_cis_dir (
    ttp_id character varying(50) NOT NULL,
    cis_id character varying(10) NOT NULL
);
 !   DROP TABLE public.mitre_cis_dir;
       public         heap 	   mirmaster    false         �            1259    16717    mitre_cis_view    VIEW     �   CREATE VIEW public.mitre_cis_view AS
 SELECT mitre_cis_dir.ttp_id,
    mitre_cis_dir.cis_id,
    cis_base.title
   FROM (public.mitre_cis_dir
     JOIN public.cis_base ON (((mitre_cis_dir.cis_id)::text = (cis_base.cis_id)::text)));
 !   DROP VIEW public.mitre_cis_view;
       public       	   mirmaster    false    218    218    228    228         }           0    0    TABLE mitre_cis_view    ACL     @   GRANT SELECT ON TABLE public.mitre_cis_view TO mirlambdareader;
          public       	   mirmaster    false    229         �            1259    16721    mitre_ens_dir    TABLE     |   CREATE TABLE public.mitre_ens_dir (
    ttp_id character varying(10) NOT NULL,
    ens_id character varying(10) NOT NULL
);
 !   DROP TABLE public.mitre_ens_dir;
       public         heap 	   mirmaster    false         �            1259    16724    mitre_ens_view    VIEW       CREATE VIEW public.mitre_ens_view AS
 SELECT mitre_ens_dir.ttp_id,
    ens_base.ens_id,
    ens_base.title
   FROM (public.ens_base
     JOIN public.mitre_ens_dir ON (((mitre_ens_dir.ens_id)::text = (ens_base.ens_id)::text)))
  ORDER BY mitre_ens_dir.ttp_id, ens_base.ens_id;
 !   DROP VIEW public.mitre_ens_view;
       public       	   mirmaster    false    230    221    221    230         ~           0    0    TABLE mitre_ens_view    ACL     @   GRANT SELECT ON TABLE public.mitre_ens_view TO mirlambdareader;
          public       	   mirmaster    false    231         �            1259    16735    mitre_nist_dir    TABLE     ~   CREATE TABLE public.mitre_nist_dir (
    ttp_id character varying(50) NOT NULL,
    nist_id character varying(10) NOT NULL
);
 "   DROP TABLE public.mitre_nist_dir;
       public         heap 	   mirmaster    false         �            1259    16738 	   nist_base    TABLE     p   CREATE TABLE public.nist_base (
    nist_id character varying(10) NOT NULL,
    title character varying(100)
);
    DROP TABLE public.nist_base;
       public         heap 	   mirmaster    false         �            1259    16741    mitre_nist_view    VIEW     �   CREATE VIEW public.mitre_nist_view AS
 SELECT mitre_nist_dir.ttp_id,
    mitre_nist_dir.nist_id,
    nist_base.title
   FROM (public.mitre_nist_dir
     JOIN public.nist_base ON (((mitre_nist_dir.nist_id)::text = (nist_base.nist_id)::text)));
 "   DROP VIEW public.mitre_nist_view;
       public       	   mirmaster    false    232    232    233    233                    0    0    TABLE mitre_nist_view    ACL     A   GRANT SELECT ON TABLE public.mitre_nist_view TO mirlambdareader;
          public       	   mirmaster    false    234         �            1259    16745    mitre_pci_dir    TABLE     |   CREATE TABLE public.mitre_pci_dir (
    ttp_id character varying(50) NOT NULL,
    pci_id character varying(10) NOT NULL
);
 !   DROP TABLE public.mitre_pci_dir;
       public         heap 	   mirmaster    false         �            1259    16748    pci_base    TABLE     n   CREATE TABLE public.pci_base (
    pci_id character varying(10) NOT NULL,
    title character varying(150)
);
    DROP TABLE public.pci_base;
       public         heap 	   mirmaster    false         �            1259    16751    mitre_pci_view    VIEW     �   CREATE VIEW public.mitre_pci_view AS
 SELECT mitre_pci_dir.ttp_id,
    mitre_pci_dir.pci_id,
    pci_base.title
   FROM (public.mitre_pci_dir
     JOIN public.pci_base ON (((mitre_pci_dir.pci_id)::text = (pci_base.pci_id)::text)));
 !   DROP VIEW public.mitre_pci_view;
       public       	   mirmaster    false    236    235    235    236         �           0    0    TABLE mitre_pci_view    ACL     @   GRANT SELECT ON TABLE public.mitre_pci_view TO mirlambdareader;
          public       	   mirmaster    false    237         �            1259    16755    nist_pci_dir    TABLE     |   CREATE TABLE public.nist_pci_dir (
    nist_id character varying(10) NOT NULL,
    pci_id character varying(10) NOT NULL
);
     DROP TABLE public.nist_pci_dir;
       public         heap 	   mirmaster    false         X          0    16660    aws_base 
   TABLE DATA           ]   COPY public.aws_base (event_rule, service, m_type, m_details_esp, m_details_eng) FROM stdin;
    public       	   mirmaster    false    216       4440.dat Y          0    16665    c5_base 
   TABLE DATA           /   COPY public.c5_base (c5_id, title) FROM stdin;
    public       	   mirmaster    false    217       4441.dat Z          0    16668    cis_base 
   TABLE DATA           1   COPY public.cis_base (cis_id, title) FROM stdin;
    public       	   mirmaster    false    218       4442.dat [          0    16671    cis_nist_dir 
   TABLE DATA           7   COPY public.cis_nist_dir (cis_id, nist_id) FROM stdin;
    public       	   mirmaster    false    219       4443.dat \          0    16674    cis_pci_dir 
   TABLE DATA           5   COPY public.cis_pci_dir (cis_id, pci_id) FROM stdin;
    public       	   mirmaster    false    220       4444.dat ]          0    16677    ens_base 
   TABLE DATA           1   COPY public.ens_base (ens_id, title) FROM stdin;
    public       	   mirmaster    false    221       4445.dat ^          0    16683    mitre_aws_dir 
   TABLE DATA           D   COPY public.mitre_aws_dir (ttp_id, service, event_rule) FROM stdin;
    public       	   mirmaster    false    222       4446.dat b          0    16707    mitre_c5_dir 
   TABLE DATA           5   COPY public.mitre_c5_dir (ttp_id, c5_id) FROM stdin;
    public       	   mirmaster    false    226       4450.dat c          0    16714    mitre_cis_dir 
   TABLE DATA           7   COPY public.mitre_cis_dir (ttp_id, cis_id) FROM stdin;
    public       	   mirmaster    false    228       4451.dat `          0    16696 	   mitre_dir 
   TABLE DATA           2   COPY public.mitre_dir (ta_id, ttp_id) FROM stdin;
    public       	   mirmaster    false    224       4448.dat d          0    16721    mitre_ens_dir 
   TABLE DATA           7   COPY public.mitre_ens_dir (ttp_id, ens_id) FROM stdin;
    public       	   mirmaster    false    230       4452.dat e          0    16735    mitre_nist_dir 
   TABLE DATA           9   COPY public.mitre_nist_dir (ttp_id, nist_id) FROM stdin;
    public       	   mirmaster    false    232       4453.dat g          0    16745    mitre_pci_dir 
   TABLE DATA           7   COPY public.mitre_pci_dir (ttp_id, pci_id) FROM stdin;
    public       	   mirmaster    false    235       4455.dat a          0    16699    mitre_ta_base 
   TABLE DATA           k   COPY public.mitre_ta_base (ta_id, url, ta_esp, ta_eng, ta_description_esp, ta_description_eng) FROM stdin;
    public       	   mirmaster    false    225       4449.dat _          0    16686    mitre_ttp_base 
   TABLE DATA           �   COPY public.mitre_ttp_base (ttp_id, url, mitigation_basic, ttp_esp, ttp_eng, ttp_description_esp, ttp_description_eng) FROM stdin;
    public       	   mirmaster    false    223       4447.dat f          0    16738 	   nist_base 
   TABLE DATA           3   COPY public.nist_base (nist_id, title) FROM stdin;
    public       	   mirmaster    false    233       4454.dat i          0    16755    nist_pci_dir 
   TABLE DATA           7   COPY public.nist_pci_dir (nist_id, pci_id) FROM stdin;
    public       	   mirmaster    false    238       4457.dat h          0    16748    pci_base 
   TABLE DATA           1   COPY public.pci_base (pci_id, title) FROM stdin;
    public       	   mirmaster    false    236       4456.dat �           2606    16759     mitre_aws_dir aws_mitre_dir_pkey 
   CONSTRAINT     w   ALTER TABLE ONLY public.mitre_aws_dir
    ADD CONSTRAINT aws_mitre_dir_pkey PRIMARY KEY (ttp_id, service, event_rule);
 J   ALTER TABLE ONLY public.mitre_aws_dir DROP CONSTRAINT aws_mitre_dir_pkey;
       public         	   mirmaster    false    222    222    222         �           2606    16761    aws_base aws_temp_2_pkey 
   CONSTRAINT     g   ALTER TABLE ONLY public.aws_base
    ADD CONSTRAINT aws_temp_2_pkey PRIMARY KEY (event_rule, service);
 B   ALTER TABLE ONLY public.aws_base DROP CONSTRAINT aws_temp_2_pkey;
       public         	   mirmaster    false    216    216         �           2606    16763    c5_base c5_base_pkey 
   CONSTRAINT     U   ALTER TABLE ONLY public.c5_base
    ADD CONSTRAINT c5_base_pkey PRIMARY KEY (c5_id);
 >   ALTER TABLE ONLY public.c5_base DROP CONSTRAINT c5_base_pkey;
       public         	   mirmaster    false    217         �           2606    16765    cis_base cis_base_pkey 
   CONSTRAINT     X   ALTER TABLE ONLY public.cis_base
    ADD CONSTRAINT cis_base_pkey PRIMARY KEY (cis_id);
 @   ALTER TABLE ONLY public.cis_base DROP CONSTRAINT cis_base_pkey;
       public         	   mirmaster    false    218         �           2606    16767    cis_nist_dir cis_nist_inh_pkey 
   CONSTRAINT     i   ALTER TABLE ONLY public.cis_nist_dir
    ADD CONSTRAINT cis_nist_inh_pkey PRIMARY KEY (cis_id, nist_id);
 H   ALTER TABLE ONLY public.cis_nist_dir DROP CONSTRAINT cis_nist_inh_pkey;
       public         	   mirmaster    false    219    219         �           2606    16769    cis_pci_dir cis_pci_inh_pkey 
   CONSTRAINT     f   ALTER TABLE ONLY public.cis_pci_dir
    ADD CONSTRAINT cis_pci_inh_pkey PRIMARY KEY (cis_id, pci_id);
 F   ALTER TABLE ONLY public.cis_pci_dir DROP CONSTRAINT cis_pci_inh_pkey;
       public         	   mirmaster    false    220    220         �           2606    16771    ens_base ens_base_pkey 
   CONSTRAINT     X   ALTER TABLE ONLY public.ens_base
    ADD CONSTRAINT ens_base_pkey PRIMARY KEY (ens_id);
 @   ALTER TABLE ONLY public.ens_base DROP CONSTRAINT ens_base_pkey;
       public         	   mirmaster    false    221         �           2606    16775    mitre_c5_dir mitre_c5_dir_pkey 
   CONSTRAINT     g   ALTER TABLE ONLY public.mitre_c5_dir
    ADD CONSTRAINT mitre_c5_dir_pkey PRIMARY KEY (ttp_id, c5_id);
 H   ALTER TABLE ONLY public.mitre_c5_dir DROP CONSTRAINT mitre_c5_dir_pkey;
       public         	   mirmaster    false    226    226         �           2606    16777 !   mitre_cis_dir mitre_cis_dir_pkey1 
   CONSTRAINT     k   ALTER TABLE ONLY public.mitre_cis_dir
    ADD CONSTRAINT mitre_cis_dir_pkey1 PRIMARY KEY (ttp_id, cis_id);
 K   ALTER TABLE ONLY public.mitre_cis_dir DROP CONSTRAINT mitre_cis_dir_pkey1;
       public         	   mirmaster    false    228    228         �           2606    16779    mitre_dir mitre_dir_pkey 
   CONSTRAINT     a   ALTER TABLE ONLY public.mitre_dir
    ADD CONSTRAINT mitre_dir_pkey PRIMARY KEY (ta_id, ttp_id);
 B   ALTER TABLE ONLY public.mitre_dir DROP CONSTRAINT mitre_dir_pkey;
       public         	   mirmaster    false    224    224         �           2606    16781     mitre_ens_dir mitre_ens_dir_pkey 
   CONSTRAINT     j   ALTER TABLE ONLY public.mitre_ens_dir
    ADD CONSTRAINT mitre_ens_dir_pkey PRIMARY KEY (ttp_id, ens_id);
 J   ALTER TABLE ONLY public.mitre_ens_dir DROP CONSTRAINT mitre_ens_dir_pkey;
       public         	   mirmaster    false    230    230         �           2606    16785 #   mitre_nist_dir mitre_nist_dir_pkey1 
   CONSTRAINT     n   ALTER TABLE ONLY public.mitre_nist_dir
    ADD CONSTRAINT mitre_nist_dir_pkey1 PRIMARY KEY (ttp_id, nist_id);
 M   ALTER TABLE ONLY public.mitre_nist_dir DROP CONSTRAINT mitre_nist_dir_pkey1;
       public         	   mirmaster    false    232    232         �           2606    16787 !   mitre_pci_dir mitre_pci_dir_pkey1 
   CONSTRAINT     k   ALTER TABLE ONLY public.mitre_pci_dir
    ADD CONSTRAINT mitre_pci_dir_pkey1 PRIMARY KEY (ttp_id, pci_id);
 K   ALTER TABLE ONLY public.mitre_pci_dir DROP CONSTRAINT mitre_pci_dir_pkey1;
       public         	   mirmaster    false    235    235         �           2606    16789     mitre_ta_base mitre_ta_base_pkey 
   CONSTRAINT     a   ALTER TABLE ONLY public.mitre_ta_base
    ADD CONSTRAINT mitre_ta_base_pkey PRIMARY KEY (ta_id);
 J   ALTER TABLE ONLY public.mitre_ta_base DROP CONSTRAINT mitre_ta_base_pkey;
       public         	   mirmaster    false    225         �           2606    16791 "   mitre_ttp_base mitre_ttp_base_pkey 
   CONSTRAINT     d   ALTER TABLE ONLY public.mitre_ttp_base
    ADD CONSTRAINT mitre_ttp_base_pkey PRIMARY KEY (ttp_id);
 L   ALTER TABLE ONLY public.mitre_ttp_base DROP CONSTRAINT mitre_ttp_base_pkey;
       public         	   mirmaster    false    223         �           2606    16793    nist_base nist_base_pkey 
   CONSTRAINT     [   ALTER TABLE ONLY public.nist_base
    ADD CONSTRAINT nist_base_pkey PRIMARY KEY (nist_id);
 B   ALTER TABLE ONLY public.nist_base DROP CONSTRAINT nist_base_pkey;
       public         	   mirmaster    false    233         �           2606    16795    nist_pci_dir nist_pci_inh_pkey 
   CONSTRAINT     i   ALTER TABLE ONLY public.nist_pci_dir
    ADD CONSTRAINT nist_pci_inh_pkey PRIMARY KEY (nist_id, pci_id);
 H   ALTER TABLE ONLY public.nist_pci_dir DROP CONSTRAINT nist_pci_inh_pkey;
       public         	   mirmaster    false    238    238         �           2606    16797    pci_base pci_base_pkey 
   CONSTRAINT     X   ALTER TABLE ONLY public.pci_base
    ADD CONSTRAINT pci_base_pkey PRIMARY KEY (pci_id);
 @   ALTER TABLE ONLY public.pci_base DROP CONSTRAINT pci_base_pkey;
       public         	   mirmaster    false    236         �           2606    16798    mitre_c5_dir fk_c5    FK CONSTRAINT     t   ALTER TABLE ONLY public.mitre_c5_dir
    ADD CONSTRAINT fk_c5 FOREIGN KEY (c5_id) REFERENCES public.c5_base(c5_id);
 <   ALTER TABLE ONLY public.mitre_c5_dir DROP CONSTRAINT fk_c5;
       public       	   mirmaster    false    217    226    4249         �           2606    16803    mitre_cis_dir fk_cis    FK CONSTRAINT     y   ALTER TABLE ONLY public.mitre_cis_dir
    ADD CONSTRAINT fk_cis FOREIGN KEY (cis_id) REFERENCES public.cis_base(cis_id);
 >   ALTER TABLE ONLY public.mitre_cis_dir DROP CONSTRAINT fk_cis;
       public       	   mirmaster    false    4251    228    218         �           2606    16808    mitre_ens_dir fk_ens    FK CONSTRAINT     y   ALTER TABLE ONLY public.mitre_ens_dir
    ADD CONSTRAINT fk_ens FOREIGN KEY (ens_id) REFERENCES public.ens_base(ens_id);
 >   ALTER TABLE ONLY public.mitre_ens_dir DROP CONSTRAINT fk_ens;
       public       	   mirmaster    false    230    4257    221         �           2606    16818    mitre_nist_dir fk_nist    FK CONSTRAINT     ~   ALTER TABLE ONLY public.mitre_nist_dir
    ADD CONSTRAINT fk_nist FOREIGN KEY (nist_id) REFERENCES public.nist_base(nist_id);
 @   ALTER TABLE ONLY public.mitre_nist_dir DROP CONSTRAINT fk_nist;
       public       	   mirmaster    false    233    4275    232         �           2606    16823    mitre_pci_dir fk_pci    FK CONSTRAINT     y   ALTER TABLE ONLY public.mitre_pci_dir
    ADD CONSTRAINT fk_pci FOREIGN KEY (pci_id) REFERENCES public.pci_base(pci_id);
 >   ALTER TABLE ONLY public.mitre_pci_dir DROP CONSTRAINT fk_pci;
       public       	   mirmaster    false    236    4279    235         �           2606    16828    mitre_dir fk_ta    FK CONSTRAINT     w   ALTER TABLE ONLY public.mitre_dir
    ADD CONSTRAINT fk_ta FOREIGN KEY (ta_id) REFERENCES public.mitre_ta_base(ta_id);
 9   ALTER TABLE ONLY public.mitre_dir DROP CONSTRAINT fk_ta;
       public       	   mirmaster    false    225    224    4265         �           2606    16833    mitre_dir fk_ttp    FK CONSTRAINT     {   ALTER TABLE ONLY public.mitre_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);
 :   ALTER TABLE ONLY public.mitre_dir DROP CONSTRAINT fk_ttp;
       public       	   mirmaster    false    223    4261    224         �           2606    16842    mitre_ens_dir fk_ttp    FK CONSTRAINT        ALTER TABLE ONLY public.mitre_ens_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);
 >   ALTER TABLE ONLY public.mitre_ens_dir DROP CONSTRAINT fk_ttp;
       public       	   mirmaster    false    4261    223    230         �           2606    16849    mitre_cis_dir fk_ttp    FK CONSTRAINT        ALTER TABLE ONLY public.mitre_cis_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);
 >   ALTER TABLE ONLY public.mitre_cis_dir DROP CONSTRAINT fk_ttp;
       public       	   mirmaster    false    223    228    4261         �           2606    16856    mitre_pci_dir fk_ttp    FK CONSTRAINT        ALTER TABLE ONLY public.mitre_pci_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);
 >   ALTER TABLE ONLY public.mitre_pci_dir DROP CONSTRAINT fk_ttp;
       public       	   mirmaster    false    223    4261    235         �           2606    16861    mitre_c5_dir fk_ttp    FK CONSTRAINT     ~   ALTER TABLE ONLY public.mitre_c5_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);
 =   ALTER TABLE ONLY public.mitre_c5_dir DROP CONSTRAINT fk_ttp;
       public       	   mirmaster    false    226    4261    223         �           2606    16866    mitre_nist_dir fk_ttp    FK CONSTRAINT     �   ALTER TABLE ONLY public.mitre_nist_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);
 ?   ALTER TABLE ONLY public.mitre_nist_dir DROP CONSTRAINT fk_ttp;
       public       	   mirmaster    false    232    223    4261                                                                                                                                                                                 4440.dat                                                                                            0000600 0004000 0002000 00000405037 14362250175 0014263 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        Persistence:IAMUser/AnomalousBehavior	AWSIAM	Protect	El uso de autenticación multi-factor, políticas de contraseñas seguras y credenciales rotativas puede mitigar los ataques de fuerza bruta	Enforcing multi-factor authentication, strong password policies, and rotating credentials may mitigate brute force attacks
Backdoor:EC2/DenialOfService.Dns	AmazonVirtualPrivatecloud	Protect	Los grupos de seguridad de VPC y las listas de control de acceso a la red (NACL) se pueden usar para restringir el acceso a los puntos finales	VPC security groups and network access control lists (NACLs) can be used to restrict access to endpoints
Impact:EC2/WinRMBruteForce	AmazonCognito	Protect	La capacidad MFA de Amazon Cognito brinda una protección significativa contra compromisos de contraseñas	Amazon Cognito MFA capability provides significant protection against password compromises
Trojan:EC2/DriveBySourceTraffic!DNS	AmazonGuardDuty	Detect	Una instancia EC2 está consultando un nombre de dominio de un host remoto que es una fuente conocida de ataques de descarga Drive-By. Recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-drivebysourcetrafficdns	An EC2 instance is querying a domain name of a remote host that is a known source of Drive-By download attacks. Recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-drivebysourcetrafficdns
iam-password-policy	AmazonInspector	Protect	El paquete de evaluación de prácticas recomendadas de Amazon Inspector puede detectar la configuración de control de seguridad relacionada con las políticas de autenticación y contraseña en los puntos finales de Linux	The Amazon Inspector Best Practices assessment package can detect security control settings related to authentication and password policies on Linux endpoints
Recon:EC2/Portscan	AmazonInspector	Protect	El paquete de evaluación de la accesibilidad de la red de Amazon Inspector puede evaluar si los componentes de la nube/red son vulnerables o no (p. ej., accesibles públicamente desde Internet)	Amazon Inspector Network Reachability assessment package can assess whether or not cloud/network components are vulnerable (e.g., publicly accessible from the Internet)
elb-tls-https-listeners-only	AmazonVirtualPrivatecloud	Protect	AWS Virtual Private Network (VPN) se puede utilizar para cifrar el tráfico que atraviesa redes que no son de confianza, lo que puede evitar que se recopile información a través de la detección de redes	AWS Virtual Private Network (VPN) can be used to encrypt traffic traversing over untrusted networks which can prevent information from being gathered via network sniffing
CryptoCurrency:EC2/BitcoinTool.B	AWSCloudWatch	Detect	Mitigación: las métricas podrían usarse para detectar si el uso de un recurso ha aumentado, como cuando un adversario secuestra un recurso para realizar tareas intensivas	Mitigation: metrics could be used to detect if the usage of a resource has increased such as when an adversary hijacks a resource to perform intensive tasks
CA_CERTIFICATE_EXPIRING_CHECK	AWSIOTDeviceDefender	Protect	"CA certificate expiring" puede identificar y resolver problemas de configuración que deben corregirse para garantizar que el cifrado SSL/TLS esté habilitado	"CA certificate expiring" can identify and resolve configuration problems that should be fixed in order to ensure SSL/TLS encryption is enabled.
multi-region-cloudtrail-enabled	AWSIAM	Protect	La condición global aws:RequestedRegion abarca todas las acciones en todos los servicios de AWS	Global condition key aws:RequestedRegion supports all actions across all AWS services
CA_CERTIFICATE_KEY_QUALITY_CHECK	AWSIOTDeviceDefender	Protect	"CA certificate key quality" puede identificar y resolver problemas de configuración que deben corregirse para garantizar que el cifrado SSL/TLS esté habilitado	"CA certificate key quality" can identify and resolve configuration problems that should be fixed in order to ensure SSL/TLS encryption is enabled.
REVOKED_CA_CERTIFICATE_STILL_ACTIVE_CHECK	AWSIOTDeviceDefender	Protect	"CA certificate revoked but device certificates still active" indica que los certificados de dispositivo firmados con un certificado de CA revocado aún están activos, lo que indica que los dispositivos que usan esos certificados están controlados por un adversario si el certificado de CA fue revocado debido a un compromiso.	"CA certificate revoked but device certificates still active" indicates that device certificates signed using a revoked CA certificate are still active, which way indicate that devices using those certificates are controlled by an adversary if the CA certificate was revoked due to compromise.
Trojan:EC2/PhishingDomainRequest!DNS	AmazonGuardDuty	Detect	Una instancia EC2 está consultando un nombre de dominio de un host remoto que es una fuente conocida de ataques. Recomendaciones/remediación: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-phishingdomainrequestdns	An EC2 instance is querying a domain name of a remote host that is a known source of attacks. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-phishingdomainrequestdns
UnauthorizedAccess:EC2/MetadataDNSRebind	AmazonGuardDuty	Detect	Una instancia EC2 está realizando búsquedas de DNS que se resuelven en el servicio de metadatos de la instancia. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-metadatadnsrebind	An EC2 instance is performing DNS lookups that resolve to the instance metadata service. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-metadatadnsrebind
UnauthorizedAccess:EC2/RDPBruteForce	AmazonGuardDuty	Detect	Una instancia EC2 puede verse involucrada en un ataque de fuerza bruta destinado a obtener contraseñas. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-rdpbruteforce	An EC2 instance may be involved in a brute force attack aimed at obtaining passwords. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-rdpbruteforce
UnauthorizedAccess:EC2/SSHBruteForce	AmazonGuardDuty	Detect	Una instancia EC2 puede verse involucrada en un ataque de fuerza bruta destinado a obtener contraseñas. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-rdpbruteforce	An EC2 instance may be involved in a brute force attack aimed at obtaining passwords. Remediation/recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-sshbruteforce
UnauthorizedAccess:EC2/TorRelay	AmazonGuardDuty	Detect	Los adversarios pueden aprovechar los recursos de los sistemas para resolver problemas intensivos en recursos que pueden afectar la disponibilidad del servicio alojado. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-torrelay	Adversaries may leverage the resources of systems in order to solve resource intensive problems which may impact hosted service availability. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-torrelay
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration	AmazonGuardDuty	Detect	Marca una instancia en la que hay indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-instancecredentialexfiltrationinsideaws	Flags an instance where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-instancecredentialexfiltrationinsideaws
access-keys-rotated	AWSConfig	Protect	Rotar las claves de acceso de modo regular está entre las buenas prácticas de seguridad. Un administrador de IAM debe deshabilitar/eliminar la clave de acceso anterior y crear una clave de acceso nueva para el usuario. Esta regla requiere un valor de rotación de clave de acceso (configuración predeterminada: 90)	Changing the access keys on a regular schedule is a security best practice. An IAM administrator must disable/delete the old AccessKey and create a new AccessKey for the user. This rule requires an access key rotation value (Config Default: 90)
alb-http-to-https-redirection-check	AWSConfig	Protect	Para ayudar a proteger los datos en tránsito, asegúrese de que su balanceador de carga de aplicaciones (ALB) redirija automáticamente las solicitudes HTTP sin cifrar a HTTPS. Debido a que pueden existir datos confidenciales, habilite el cifrado en tránsito para ayudar a proteger esos datos	To help protect data in transit, ensure that your Application Load Balancer automatically redirects unencrypted HTTP requests to HTTPS. Because sensitive data can exist, enable encryption in transit to help protect that data
api-gw-ssl-enabled	AWSConfig	Detect	Asegúrese de que las etapas de la API REST de Amazon API Gateway estén configuradas con certificados SSL para permitir que los sistemas backend autentiquen que las solicitudes se originan en API Gateway	Ensure Amazon API Gateway REST API stages are configured with SSL certificates to allow backend systems to authenticate that requests originate from API Gateway
autoscaling-group-elb-healthcheck-required	AWSConfig	Protect	Las comprobaciones de estado en Balanceadores para los grupos de autoescalado (Amazon Elastic Compute Cloud Auto Scaling) permiten mantener la capacidad y disponibilidad adecuadas de sus servicios; si una instancia no responde, el tráfico se envía a una nueva instancia de Amazon EC2	The Elastic Load Balancer health checks for Amazon Elastic Compute Cloud Auto Scaling groups support maintenance of adequate capacity and availability. If an instance is not reporting back, traffic is sent to a new Amazon EC2 instance
autoscaling-launch-config-public-ip-disabled	AWSConfig	Protect	Si configura sus interfaces de red con una dirección IP pública, los recursos asociados a esas interfaces de red son accesibles desde Internet. Esto puede permitir el acceso no deseado a sus aplicaciones o servidores. Si es necesario, aplique otras medidas de seguridad como VPN, NACL, grupos de seguridad, certificados SSL/TLS o autenticación	If you configure your Network Interfaces with a public IP address, then the associated resources to those Network Interfaces are reachable from the internet. This may allow unintended access to your applications or servers. If needed, apply others security measures like VPN, NACL, Security Groups, SSL/TLS certificates o authentication
cloud-trail-cloud-watch-logs-enabled	AWSConfig	Protect	Utilice Amazon CloudWatch para recopilar y administrar de forma centralizada la actividad de eventos de registro. La inclusión de datos de AWS CloudTrail proporciona detalles de la actividad de llamadas a la API dentro de su cuenta de AWS. Si es deshabilitado, puede deberse a una táctica de Evasión de Defensa	Use Amazon CloudWatch to centrally collect and manage log event activity. Inclusion of AWS CloudTrail data provides details of API call activity within your AWS account. If disabled, it may be due to a Defense Evasion tactic
cloudtrail-security-trail-enabled	AWSConfig	Protect	Esta regla ayuda a garantizar el uso de las mejores prácticas de seguridad recomendadas por AWS para AWS CloudTrail al verificar la habilitación de varias configuraciones. Estos incluyen el uso de cifrado de registros, validación de registros y habilitación de AWS CloudTrail en varias regiones	This rule helps ensure the use of AWS recommended security best practices for AWS CloudTrail, by checking for the enablement of multiple settings. These include the use of log encryption, log validation, and enabling AWS CloudTrail in multiple regions
cloudwatch-alarm-action-check	AWSConfig	Detect	Esta regla requiere un valor para alarmActionRequired:verdadero, insuficienteDataActionRequired:verdadero, okActionRequired:falso. Como buena práctica de seguridad está el empleo de alarmas de Amazon CloudWatch para monitorizar la actividad de recursos de AWS https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html	This rule requires a value for alarmActionRequired (Config Default: True), insufficientDataActionRequired (Config Default: True), okActionRequired (Config Default: False). To use Amazon CloudWatch alarms is a best practice to monitoring AWS resources activity https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
codebuild-project-envvar-awscred-check	AWSConfig	Protect	Asegúrese de que las credenciales de autenticación AWS_ACCESS_KEY_ID y AWS_SECRET_ACCESS_KEY no existan en los entornos de proyectos de AWS Codebuild. No almacene estas variables en texto claro. El almacenamiento de estas variables en texto sin cifrar conduce a la exposición no deseada de los datos y al acceso no autorizado	Ensure authentication credentials AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY do not exist within AWS Codebuild project environments. Do not store these variables in clear text. Storing these variables in clear text leads to unintended data exposure and unauthorized access
codebuild-project-source-repo-url-check	AWSConfig	Protect	Asegúrese de que la URL del repositorio de origen de GitHub o Bitbucket no contenga tokens de acceso personal, nombre de usuario y contraseña en los entornos de proyecto de AWS Codebuild. Use OAuth en lugar de tokens de acceso personal o nombre de usuario y contraseña para otorgar autorización para acceder a los repositorios de GitHub o Bitbucket	Ensure the GitHub or Bitbucket source repository URL does not contain personal access tokens, user name and password within AWS Codebuild project environments. Use OAuth instead of personal access tokens or a user name and password to grant authorization for accessing GitHub or Bitbucket repositories
dynamodb-throughput-limit-check	AWSConfig	Detect	Esta regla de AWS Config comprueba si el rendimiento de DynamoDB aprovisionado se acerca al límite máximo de su cuenta (80% de forma predeterminada). De encontrarse en estado no-conforme, puede deberse a estar bajo tácticas de Impacto o Ejecución	This AWS Config rule checks if provisioned DynamoDB throughput is approaching the maximum limit for your account (by default 80%). If it is in a non-conforming state, it may be due to Impact or Execution tactics
ec2-ebs-encryption-by-default	AWSConfig	Protect	Para ayudar a proteger los datos en reposo, asegúrese de que el cifrado esté habilitado para sus volúmenes de Amazon Elastic Block Store (Amazon EBS). Debido a que los datos confidenciales pueden existir en reposo en estos volúmenes, habilite el cifrado en reposo para ayudar a proteger esos datos	To help protect data at rest, ensure that encryption is enabled for your Amazon Elastic Block Store (Amazon EBS) volumes. Because sensitive data can exist at rest in these volumes, enable encryption at rest to help protect that data
ec2-imdsv2-check	AWSConfig	Protect	Habilite el método Instance Metadata Service Version 2 (IMDSv2) para ayudar a proteger el acceso y el control de los metadatos de la instancia de Amazon Elastic Compute Cloud (Amazon EC2) (para restringir los cambios en los metadatos de la instancia) https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html	Enable the Instance Metadata Service Version 2 (IMDSv2) method to help protect access and control of Amazon Elastic Compute Cloud (Amazon EC2) instance metadata (to restrict changes to instance metadata) https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
ec2-instance-managed-by-systems-manager	AWSConfig	Protect	AWS Systems Manager proporciona detalles de configuraciones de sistemas e instalaciones de software. Habilitar AWS Systems Manager permite que las organizaciones administren instancias de Amazon Elastic Compute Cloud y monitoricen un inventario de plataformas de software y de aplicaciones	AWS Systems Manager provides detailed system configurations and software installations. Enabling AWS Systems Manager grants organizations manage Amazon Elastic Compute Cloud instances and obtain software platforms and applications inventory
ssm-document-not-public	AWSConfig	Protect	Asegúrese de que los documentos de AWS Systems Manager (SSM) no son públicos, ya que esto puede permitir el acceso involuntario a sus documentos SSM. Un documento SSM público puede exponer información sobre su cuenta, recursos y procesos internos	Ensure AWS Systems Manager (SSM) documents are not public, as this may allow unintended access to your SSM documents. A public SSM document can expose information about your account, resources and internal processes
s3-bucket-public-write-prohibited	AWSConfig	Protect	Gestione el acceso a los recursos en la nube de AWS permitiendo únicamente a los usuarios, procesos y dispositivos autorizados el acceso a los buckets de Amazon Simple Storage Service (Amazon S3). La gestión del acceso debe ser coherente con la clasificación de los datos	Manage access to resources in the AWS Cloud by only allowing authorized users, processes, and devices access to Amazon Simple Storage Service (Amazon S3) buckets. The management of access should be consistent with the classification of the data
sagemaker-endpoint-configuration-kms-key-configured	AWSConfig	Protect	Para ayudar a proteger los datos en reposo, asegúrese de que el cifrado con AWS Key Management Service (AWS KMS) esté habilitado para su endpoint de SageMaker. Dado que los datos sensibles pueden existir en reposo en el endpoint de SageMaker, habilite el cifrado en reposo para ayudar a proteger esos datos	To help protect data at rest, ensure encryption with AWS Key Management Service (AWS KMS) is enabled for your SageMaker endpoint. Because sensitive data can exist at rest in SageMaker endpoint, enable encryption at rest to help protect that data
sagemaker-notebook-instance-kms-key-configured	AWSConfig	Protect	Para ayudar a proteger los datos en reposo, asegúrese de que el cifrado con AWS Key Management Service (AWS KMS) esté habilitado para su cuaderno SageMaker. Dado que los datos sensibles pueden existir en reposo en el cuaderno SageMaker, habilite el cifrado en reposo para ayudar a proteger esos datos	To help protect data at rest, ensure encryption with AWS Key Management Service (AWS KMS) is enabled for your SageMaker notebook. Because sensitive data can exist at rest in SageMaker notebook, enable encryption at rest to help protect that data
s3-bucket-public-read-prohibited	AWSConfig	Protect	Gestione el acceso a los recursos en la nube de AWS permitiendo únicamente a los usuarios, procesos y dispositivos autorizados el acceso a los buckets de Amazon Simple Storage Service (Amazon S3). La gestión del acceso debe ser coherente con la clasificación de los datos	Manage access to resources in the AWS Cloud by only allowing authorized users, processes, and devices access to Amazon Simple Storage Service (Amazon S3) buckets. The management of access should be consistent with the classification of the data
s3-bucket-level-public-access-prohibited	AWSConfig	Protect	Administre el acceso a los recursos en la nube de AWS garantizando que no se pueda acceder públicamente a los buckets de Amazon Simple Storage Service (Amazon S3). Esta regla ayuda a mantener los datos confidenciales a salvo de usuarios remotos no autorizados impidiendo el acceso público a nivel de bucket	Manage access to resources in the AWS Cloud by ensuring that Amazon Simple Storage Service (Amazon S3) buckets cannot be publicly accessed. This rule helps keeping sensitive data safe from unauthorized remote users by preventing public access at the bucket level
securityhub-enabled	AWSConfig	Protect	AWS Security Hub ayuda a monitorear el personal, las conexiones, los dispositivos y el software no autorizados. AWS Security Hub agrega, organiza y prioriza las alertas de seguridad o los hallazgos de varios servicios de AWS	AWS Security Hub helps to monitor unauthorized personnel, connections, devices, and software. AWS Security Hub aggregates, organizes, and prioritizes the security alerts, or findings, from multiple AWS services
encrypted-volumes	AWSKeyManagementService	Protect	Este servicio proporciona una alternativa más segura al almacenamiento de claves de cifrado en el sistema de archivos	This service provides a more secure alternative to storing encryption keys in the file system
aws:num-listening-udp-ports	AWSIOTDeviceDefender	Detect	"Listening UDP port count" con valores fuera de las normas esperadas puede indicar que los dispositivos se están comunicando a través de puertos/protocolos inesperados	"Listening UDP port count" outside of expected norms may indicate that devices are communicating via unexpected ports/protocols.
3.4 Ensure a log metric filter and alarm exist for IAM policy changes 	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
aws:num-messages-received	AWSIOTDeviceDefender	Detect	Los valores de "Messages received" fuera de las normas esperadas pueden indicar que los dispositivos están enviando y/o recibiendo tráfico no estándar	"Messages received" values outside of expected norms may indicate that devices are sending and/or receiving non-standard traffic.
restricted-ssh	AWSConfig	Protect	Los grupos de seguridad de Amazon Elastic Compute Cloud (Amazon EC2) pueden ayudar a administrar el acceso a la red proporcionando un filtrado de estado del tráfico de red de entrada y salida a los recursos de AWS. No permitir el tráfico de entrada (o remoto) desde 0.0.0.0/0 al puerto 22 en sus recursos le ayuda a restringir el acceso remoto	Amazon Elastic Compute Cloud (Amazon EC2) Security Groups can help manage network access by providing stateful filtering of ingress and egress network traffic to AWS resources. Not allowing ingress (or remote) traffic from 0.0.0.0/0 to port 22 on your resources help you restricting remote access
redshift-cluster-kms-enabled	AWSConfig	Protect	Para ayudar a proteger los datos en reposo, asegúrese de que el cifrado con AWS Key Management Service (AWS KMS) está habilitado para su clúster de Amazon Redshift. Dado que los datos sensibles pueden existir en reposo en los clústeres de Redshift, habilite el cifrado en reposo para ayudar a proteger esos datos	To help protect data at rest, ensure encryption with AWS Key Management Service (AWS KMS) is enabled for your Amazon Redshift cluster. Because sensitive data can exist at rest in Redshift clusters, enable encryption at rest to help protect that data
restricted-common-ports	AWSConfig	Protect	Gestione el acceso a los recursos en la nube de AWS asegurándose de que los puertos comunes están restringidos en los grupos de seguridad de Amazon EC2. No restringir los puertos a fuentes de confianza le expone a ataques. Esta regla le permite establecer opcionalmente los parámetros blockedPort1 a blockedPort5 (por defecto 20,21,3389,3306,4333)	Manage access to resources in the AWS Cloud by ensuring common ports are restricted on Amazon Elastic Compute Cloud security groups. Not restricting access to ports to trusted sources can lead to attacks. This rule allows you to optionally set blockedPort1 - blockedPort5 parameters (Config Defaults: 20,21,3389,3306,4333)
Recon:EC2/Portscan	AmazonVirtualPrivatecloud	Protect	Los grupos de seguridad de VPC y las listas de control de acceso a la red (NACL) pueden filtrar el tráfico de red tanto interno como externo	VPC security groups and network access control lists (NACLs) can filter both internal and external network traffic
elb-cross-zone-load-balancing-enabled	AWSNetworkFirewall	Protect	Las NACL y los grupos de seguridad tienen la capacidad de filtrar, descartar o alertar sobre el tráfico en función del protocolo de red, así como realizar una inspección profunda de paquetes en la carga útil	NACLs and Security Groups have the ability to pass, drop, or alert on traffic based on the network protocol as well as perform deep packet inspection on the payload
redshift-cluster-public-access-check	AWSConfig	Protect	Administre el acceso a los recursos en la nube de AWS asegurándose de que los clústeres de Amazon Redshift no sean públicos. Los clústeres de Amazon Redshift pueden contener información y principios sensibles y se requiere un control de acceso para dichas cuentas	Manage access to resources in the AWS Cloud by ensuring that Amazon Redshift clusters are not public. Amazon Redshift clusters can contain sensitive information and principles and access control is required for such accounts
redshift-cluster-maintenancesettings-check	AWSConfig	Protect	Esta regla garantiza que los clústeres de Amazon Redshift tengan la configuración preferida para los periodos de retención de instantáneas automatizados para la base de datos. Esta regla requiere que se configure el allowVersionUpgrade:true	This rule ensures that Amazon Redshift clusters have the preferred maintenance windows and automated snapshot retention periods for the database. This rule requires you to set the allowVersionUpgrade:true
Impact:EC2/WinRMBruteForce	AWSSSO	Protect	Mitigación: puede proteger contra técnicas de fuerza bruta al habilitar la autenticación de múltiples factores	Mitigation: may protect against brute force techniques by enabling multi-factor authentication
UnauthorizedAccess:EC2/SSHBruteForce	AmazonInspector	Protect	El paquete de evaluación de prácticas recomendadas de Amazon Inspector puede detectar la configuración de control de seguridad relacionada con las políticas de autenticación y contraseña en los puntos finales de Linux	The Amazon Inspector Best Practices assessment package can detect security control settings related to authentication and password policies on Linux endpoints
aws:num-messages-sent	AWSIOTDeviceDefender	Detect	Los valores de "Messages sent" fuera de las normas esperadas pueden indicar que los dispositivos están enviando y/o recibiendo tráfico no estándar	"Messages sent" values outside of expected norms may indicate that devices are sending and/or receiving non-standard traffic.
aws:all-packets-in	AWSIOTDeviceDefender	Detect	Los valores de "Packets in" fuera de las normas esperadas pueden indicar tráfico relacionado con actividades de secuestro de recursos	"Packets in" values outside of expected norms may indicate traffic related to resource hijacking activities.
Exfiltration:IAMUser/AnomalousBehavior	AWSSSO	Protect	Mitigación: protéjase contra el uso malintencionado de cuentas válidas mediante la implementación de acceso detallado y con privilegios mínimos mediante el uso de conjuntos de permisos	Mitigation: protect against malicious use of valid accounts by implementing fine grained and least privilege access through use of permission sets
ec2-instances-in-vpc	AWSConfig	Protect	Implemente instancias de Amazon Elastic Compute Cloud (Amazon EC2) dentro de Amazon Virtual Private Cloud (Amazon VPC) para habilitar la comunicación segura entre una instancia y otros servicios dentro de Amazon VPC. Todo el tráfico permanece seguro sin necesidad de una puerta de enlace a Internet, un dispositivo NAT o una conexión VPN	Deploy Amazon Elastic Compute Cloud (Amazon EC2) instances within an Amazon Virtual Private Cloud (Amazon VPC) to enable secure communication between an instance and other services within the amazon VPC. All traffic remains securely without requiring an internet gateway, NAT device, or VPN connection
elasticache-redis-cluster-automatic-backup-check	AWSConfig	Protect	Las copias de seguridad automáticas pueden ayudar a protegerse contra la pérdida de datos. Si ocurre una falla, puede crear un nuevo clúster, que restaura sus datos desde la copia de seguridad más reciente. Cuando las copias de seguridad automáticas están habilitadas, Amazon ElastiCache crea una copia de seguridad del clúster diariamente	Automatic backups can help guard against data loss. If a failure occurs, you can create a new cluster, which restores your data from the most recent backup. When automatic backups are enabled, Amazon ElastiCache creates a backup of the cluster on a daily basis
elastic-beanstalk-managed-updates-enabled	AWSConfig	Protect	Habilitar las actualizaciones de la plataforma administrada para un entorno de Amazon Elastic Beanstalk garantiza que se instalen las últimas correcciones, actualizaciones y características de la plataforma disponibles para el entorno. Mantenerse al día con la instalación de parches es una buena práctica para proteger los sistemas	Enabling managed platform updates for an Amazon Elastic Beanstalk environment ensures that the latest available platform fixes, updates, and features for the environment are installed. Keeping up to date with patch installation is a best practice in securing systems
elasticsearch-logs-to-cloudwatch	AWSConfig	Detect	Asegúrese de que los dominios de Amazon OpenSearch Service tengan registros de errores habilitados y transmitidos a Amazon CloudWatch Logs para retención y respuesta. Los registros de errores de dominio pueden ayudar con las auditorías de seguridad y acceso, y pueden ayudar a diagnosticar problemas de disponibilidad	Ensure Amazon OpenSearch Service domains have error logs enabled and streamed to Amazon CloudWatch Logs for retention and response. Domain error logs can assist with security and access audits, and can help to diagnose availability issues
api-gw-associated-with-waf	AWSConfig	Detect	AWS WAF le permite configurar un conjunto de reglas (ACL web) que permiten, bloquean o cuentan las solicitudes web en función de las reglas y condiciones de seguridad web personalizables que defina. Asegúrese de que su etapa de Amazon API Gateway esté asociada con una ACL web de WAF para protegerla de ataques maliciosos	AWS WAF enables you to configure a set of rules (called a web access control list (web ACL)) that allow, block, or count web requests based on customizable web security rules and conditions that you define. Ensure your Amazon API Gateway stage is associated with a WAF Web ACL to protect it from malicious attack
iam-user-mfa-enabled	AWSConfig	Protect	Habilite esta regla para restringir el acceso a los recursos en la nube de AWS. Esta regla garantiza que la autenticación multifactor (MFA) esté habilitada para todos los usuarios de IAM. La MFA añade una capa adicional de protección además del nombre de usuario y la contraseña y reduce los incidentes de cuentas comprometidas	Enable this rule to restrict access to resources in the AWS Cloud. This rule ensures multi-factor authentication (MFA) is enabled for all IAM users. MFA adds an extra layer of protection on top of a user name and password. Reduce the incidents of compromised accounts by requiring MFA for IAM users
Exfiltration:S3/MaliciousIPCaller	AWSNetworkFirewall	Protect	Las NACL y los grupos de seguridad tienen la capacidad de filtrar, descartar o alertar sobre el tráfico en función del protocolo de red, así como realizar una inspección profunda de paquetes en la carga útil	NACLs and Security Groups have the ability to pass, drop, or alert on traffic based on the network protocol as well as perform deep packet inspection on the payload
Impact:IAMUser/AnomalousBehavior	AWSIAM	Protect	Mitigación: fuerce el uso de credenciales de seguridad temporales mediante el uso de rol de IAM	Mitigation: retrieve temporary security credentials using an IAM role
REVOKED_DEVICE_CERTIFICATE_STILL_ACTIVE_CHECK	AWSIOTDeviceDefender	Protect	"Revoked device certificate still active" sugiere que un adversario puede estar usando clones de dispositivos comprometidos para aprovechar su acceso	"Revoked device certificate still active" suggest that an adversary may be using clones of compromised devices to leverage their access.
UnauthorizedAccess:S3/TorIPCaller	AmazonGuardDuty	Detect	Los adversarios podrían cifrar o destruir datos y archivos en sistemas específicos para interrumpir la disponibilidad de sistemas, servicios y recursos de red. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#unauthorizedaccess-s3-toripcaller	Adversaries may encrypt or destroy data and files on specific systems to interrupt availability to systems, services, and network resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#unauthorizedaccess-s3-toripcaller
rds-instance-public-access-check	AWSConfig	Protect	Administrar el acceso a los recursos en la nube de AWS garantizando que las instancias de Amazon Relational Database Service (Amazon RDS) no sean públicas. Las instancias de bases de datos de Amazon RDS pueden contener información sensible, y se requieren principios y control de acceso para dichas cuentas	Manage access to resources in the AWS Cloud by ensuring that Amazon Relational Database Service (Amazon RDS) instances are not public. Amazon RDS database instances can contain sensitive information, and principles and access control is required for such accounts
rds-logging-enabled	AWSConfig	Detect	Para facilitar el registro y la monitorización en su entorno, asegúrese de que el registro de Amazon Relational Database Service (Amazon RDS) está habilitado. Con el registro de Amazon RDS, puede capturar eventos como conexiones, desconexiones, consultas o tablas consultadas	To help with logging and monitoring within your environment, ensure Amazon Relational Database Service (Amazon RDS) logging is enabled. With Amazon RDS logging, you can capture events such as connections, disconnections, queries, or tables queried
rds-snapshot-encrypted	AWSConfig	Protect	Asegúrese de que el cifrado esté habilitado para sus instantáneas de Amazon Relational Database Service (Amazon RDS). Debido a que los datos confidenciales pueden existir en reposo, habilite el cifrado en reposo para ayudar a proteger esos datos	Ensure that encryption is enabled for your Amazon Relational Database Service (Amazon RDS) snapshots. Because sensitive data can exist at rest, enable encryption at rest to help protect that data
multi-region-cloudtrail-enabled	AWSConfig	Protect	AWS CloudTrail registra las acciones de la consola de administración de AWS y las llamadas a la API. CloudTrail entregará archivos de registro de todas las regiones de AWS a su cubo de S3 si MULTI_REGION_CLOUD_TRAIL_ENABLED está habilitado	AWS CloudTrail records AWS Management Console actions and API calls. CloudTrail will deliver log files from all AWS Regions to your S3 bucket if MULTI_REGION_CLOUD_TRAIL_ENABLED is enabled
rds-in-backup-plan	AWSConfig	Protect	Para ayudar con los procesos de respaldo de datos, asegúrese de que sus instancias de Amazon Relational Database Service sean parte de un plan de respaldo de AWS. AWS Backup es un servicio de copia de seguridad completamente administrado https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html	To help with data back-up processes, ensure your Amazon Relational Database Service instances are a part of an AWS Backup plan. AWS Backup is a fully managed backup service with a policy-based backup solution https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html
iam-user-mfa-enabled	AmazonCognito	Protect	La capacidad MFA de Amazon Cognito brinda una protección significativa contra compromisos de contraseñas	Amazon Cognito MFA capability provides significant protection against password compromises
Recon:EC2/Portscan	AWSNetworkFirewall	Protect	Las NACL y los grupos de seguridad tienen la capacidad de filtrar, descartar o alertar sobre el tráfico en función del protocolo de red, así como realizar una inspección profunda de paquetes en la carga útil	NACLs and Security Groups have the ability to pass, drop, or alert on traffic based on the network protocol as well as perform deep packet inspection on the payload
sns-encrypted-kms	AWSConfig	Protect	Para ayudar a proteger los datos en reposo, asegúrese de que sus temas de Amazon Simple Notification Service (Amazon SNS) requieren cifrado mediante AWS Key Management Service (AWS KMS). Dado que los datos sensibles pueden existir en reposo en los mensajes publicados, habilite el cifrado en reposo para ayudar a proteger esos datos	To help protect data at rest, ensure that your Amazon Simple Notification Service (Amazon SNS) topics require encryption using AWS Key Management Service (AWS KMS). Because sensitive data can exist at rest in published messages, enable encryption at rest to help protect that data
iam-user-unused-credentials-check	AWSConfig	Protect	AWS Identity and Access Management puede ayudarle con los permisos de acceso y las autorizaciones recuperando las contraseñas y claves de acceso que no se han utilizado durante un periodo de tiempo determinado. Estas credenciales se deben desactivar o eliminar. Esta regla requiere que se establezca un valor para el maxCredentialUsageAge (90)	AWS Identity and Access Management can help you with access permissions and authorizations by checking for IAM passwords and access keys that are not used for a specified time period. If these unused credentials are identified, you should disable or remove the credentials. This rule requires you to set a value to the maxCredentialUsageAge (90)
3.1 Ensure a log metric filter and alarm exist for unauthorized API calls	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
internet-gateway-authorized-vpc-only	AWSConfig	Detect	Controle el acceso a los recursos de la nube de AWS asegurándose de que las puertas de enlace de Internet se asocien sólo a redes virtuales (Amazon VPC) autorizadas. Una mala asignación de puertas de enlace puede dar lugar a un acceso no autorizado a los recursos de la VPC de Amazon	Manage access to resources in the AWS Cloud by ensuring that internet gateways are only attached to authorized Amazon Virtual Private Cloud (Amazon VPC). Internet gateways can potentially lead to unauthorized access to Amazon VPC resources
Backdoor:EC2/DenialOfService.Dns	AWSNetworkFirewall	Protect	Las NACL y los grupos de seguridad tienen la capacidad de filtrar, descartar o alertar sobre el tráfico en función del protocolo de red, así como realizar una inspección profunda de paquetes en la carga útil	NACLs and Security Groups have the ability to pass, drop, or alert on traffic based on the network protocol as well as perform deep packet inspection on the payload
Discovery:IAMUser/AnomalousBehavior	AWSOrganizations	Protect	Mitigación: puede proteger contra el descubrimiento de cuentas en la nube al segmentar las cuentas en unidades organizativas separadas	Mitigation: may protect against cloud account discovery by segmenting accounts into separate organizational units
rds-storage-encrypted	AWSRDS	Protect	AWS RDS admite el cifrado del almacenamiento subyacente para instancias de bases de datos, copias de seguridad, réplicas de lectura e instantáneas mediante el algoritmo de cifrado AES-256	AWS RDS supports the encryption of the underlying storage for database instances, backups, read replicas, and snapshots using the AES-256 encryption algorithm
elb-logging-enabled	AWSConfig	Detect	Asegúrese de que el registro del ELB está activado. Los datos recogidos proporcionan información detallada sobre las solicitudes enviadas al ELB. Cada registro contiene información como la hora en que se recibió la solicitud, la dirección IP del cliente, las latencias, las rutas de solicitud y las respuestas del servidor	Ensure ELB logging is enabled. The collected data provides detailed information about requests sent to the ELB. Each log contains information such as the time the request was received, the client´s IP address, latencies, request paths, and server responses
elb-predefined-security-policy-ssl-check	AWSConfig	Detect	Para ayudar a proteger los datos en tránsito, asegúrese de que sus escuchas SSL de Classic Elastic Load Balancing utilizan una política de seguridad predefinida. Esta regla requiere que establezca una política de seguridad predefinida para sus escuchas SSL. La política de seguridad predeterminada es ELBSecurityPolicy-TLS-1-2-2017-0	To help protect data in transit, ensure that your Classic Elastic Load Balancing SSL listeners are using a predefined security policy. This rule requires that you set a predefined security policy for your SSL listeners. The default security policy is: ELBSecurityPolicy-TLS-1-2-2017-0
redshift-backup-enabled	AWSConfig	Protect	Para facilitar los procesos de copia de seguridad de los datos, asegúrese de que sus clústeres de Amazon Redshift tengan instantáneas automatizadas. Cuando las instantáneas automatizadas están habilitadas, Redshift realiza periódicamente instantáneas de ese clúster. Por defecto, cada ocho horas o cada 5 GB de cambios de datos por nodo	To help with data back-up processes, ensure your Amazon Redshift clusters have automated snapshots. When automated snapshots are enabled for a cluster, Redshift periodically takes snapshots of that cluster. By default, Redshift takes a snapshot every eight hours or every 5 GB per node of data changes, or whichever comes first
DEVICE_CERTIFICATE_EXPIRING_CHECK	AWSIOTDeviceDefender	Protect	"Device certificate expiring" puede identificar y resolver problemas de configuración que deben solucionarse para garantizar que el cifrado SSL/TLS esté habilitado	"Device certificate expiring" can identify and resolve configuration problems that should be fixed in order to ensure SSL/TLS encryption is enabled.
DEVICE_CERTIFICATE_KEY_QUALITY_CHECK	AWSIOTDeviceDefender	Protect	"Device certificate key quality" puede identificar y resolver problemas de configuración que deben solucionarse para garantizar que el cifrado SSL/TLS esté habilitado	"Device certificate key quality" can identify and resolve configuration problems that should be fixed in order to ensure SSL/TLS encryption is enabled.
3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
DEVICE_CERTIFICATE_SHARED_CHECK	AWSIOTDeviceDefender	Protect	"Device certificate shared" puede identificar y resolver problemas de configuración que deben solucionarse para garantizar que el cifrado SSL/TLS esté habilitado	"Device certificate shared" can identify and resolve configuration problems that should be fixed in order to ensure SSL/TLS encryption is enabled.
3.3 Ensure a log metric filter and alarm exist for usage of "root" account 	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
3.4 Ensure a log metric filter and alarm exist for IAM policy changes	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) 	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
DefenseEvasion:IAMUser/AnomalousBehavior	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#defenseevasion-iam-anomalousbehavior	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#defenseevasion-iam-anomalousbehavior
root-account-mfa-enabled	AWSConfig	Protect	Asegúrese de que la MFA de hardware esté habilitada para el usuario raíz. El usuario raíz es el usuario con más privilegios en una cuenta de AWS. La MFA añade una capa adicional de protección para el nombre de usuario y la contraseña. Al requerir MFA para el usuario raíz, puede reducir los incidentes de cuentas AWS comprometidas	Manage access to resources in the AWS Cloud by ensuring MFA is enabled for the root user. The root user is the most privileged user in an AWS account. The MFA adds an extra layer of protection for a user name and password. By requiring MFA for the root user, you can reduce the incidents of compromised AWS accounts
aws:num-authorization-failures	AWSIOTDeviceDefender	Detect	El recuento de "Authorization failures" por encima de un umbral típico pueden indicar que un dispositivo comprometido está intentando utilizar su conexión a AWS IoT para acceder a recursos para los que no tiene acceso y se le niega	"Authorization failures" counts above a typical threshold may indicate that a compromised device is attempting to use its connection to AWS IoT to access resources for which it does not have access and being denied.
aws:all-bytes-in	AWSIOTDeviceDefender	Detect	Los valores de "Bytes in" fuera de las normas esperadas pueden indicar tráfico relacionado con actividades de secuestro de recursos	"Bytes in" values outside of expected norms may indicate traffic related to resource hijacking activities.
elb-tls-https-listeners-only	AWSRDS	Protect	AWS RDS Proxy admite conexiones TLS/SSL a instancias de bases de datos que protegen contra ataques de rastreo de red	AWS RDS Proxy support TLS/SSL connections to database instances which protects against network sniffing attacks
3.12 Ensure a log metric filter and alarm exist for changes to network gateways 	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
Recon:EC2/PortProbeUnprotectedPort	AWSWebApplicationFirewall	Protect	La aplicación de conjuntos de reglas AWSManagedRulesCommonRuleSet protege contra bots que ejecutan escaneos en aplicaciones web. https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html	Applying AWSManagedRulesCommonRuleSet rule sets protects against bots that run scans against web applications. https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
aws:all-bytes-out	AWSIOTDeviceDefender	Detect	Los valores de "Bytes fuera" fuera de las normas esperadas puede indicar que el dispositivo está enviando y/o recibiendo tráfico no estándar	"Bytes out" outside of expected norms may indicate that the device is sending and/or receiving non-standard traffic.
aws:destination-ip-addresses	AWSIOTDeviceDefender	Detect	"Destination Ips" fuera de los rangos de direcciones IP esperados pueden sugerir que un dispositivo se está comunicando con dispositivos inesperados	"Destination Ips" outside of expected IP address ranges may suggest that a device is communicating with unexpected devices.
aws:num-established-tcp-connections	AWSIOTDeviceDefender	Detect	"Established TCP connections count" con valores fuera de las normas esperadas puede indicar que los dispositivos se están comunicando a través de puertos/protocolos inesperados	"Established TCP connections count" outside of expected norms may indicate that devices are communicating via unexpected ports/protocols.
aws:num-listening-tcp-ports	AWSIOTDeviceDefender	Detect	Los valores de "Listening TCP port count" fuera de las normas esperadas pueden indicar tráfico relacionado con actividades de secuestro de recursos	"Listening TCP port count" values outside of expected norms may indicate  traffic related to resource hijacking activities.
aws:listening-tcp-ports	AWSIOTDeviceDefender	Detect	Los valores de "Listening TCP ports" fuera de las normas esperadas pueden indicar tráfico relacionado con actividades de secuestro de recursos	"Listening TCP ports" values outside of expected norms may indicate  traffic related to resource hijacking activities.
aws:listening-udp-ports	AWSIOTDeviceDefender	Detect	Los valores de "Listening UDP ports" fuera de las normas esperadas pueden indicar tráfico relacionado con actividades de secuestro de recursos	"Listening UDP ports" values outside of expected norms may indicate  traffic related to resource hijacking activities.
aws:all-packets-out	AWSIOTDeviceDefender	Detect	"Packets out" fuera de las normas esperadas puede indicar que el dispositivo está enviando y/o recibiendo tráfico no estándar	"Packets out" outside of expected norms may indicate that the device is sending and/or receiving non-standard traffic.
acm-certificate-expiration-check	AWSConfig	Protect	Asegúrese de que la integridad de la red esté protegida mediante certificados X509 emitidos por AWS ACM. Estos certificados deben ser válidos y no caducados. Esta regla requiere un valor para daysToExpiration (valor de Prácticas recomendadas de seguridad fundamental de AWS: 90)	Ensure network integrity is protected by ensuring X509 certificates are issued by AWS ACM. These certificates must be valid and unexpired. This rule requires a value for daysToExpiration (AWS Foundational Security Best Practices value: 90)
Recon:EC2/PortProbeEMRUnprotectedPort	AmazonGuardDuty	Detect	There is an attempt to get a list of services running on a remote host. Remediation/recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portprobeemrunprotectedport	There is an attempt to get a list of services running on a remote host. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portprobeemrunprotectedport
IAM users with suspicious activity	AWSSecurityHub	Detect	Insights: detecta actividad sospechosa de cuentas de AWS que podría indicar que un adversario está aprovechando cuentas válidas	Insights: detects suspicious activity by AWS accounts which could indicate valid accounts being leveraged by an adversary
iam-user-mfa-enabled	AWSSSO	Protect	Mitigación: puede proteger contra técnicas de fuerza bruta al habilitar la autenticación de múltiples factores	Mitigation: may protect against brute force techniques by enabling multi-factor authentication
Trojan:EC2/DriveBySourceTraffic!DNS	AmazonInspector	Protect	Amazon Inspector puede detectar vulnerabilidades conocidas en varios puntos finales de Windows y Linux	Amazon Inspector can detect known vulnerabilities on various Windows and Linux endpoints
3.13 Ensure a log metric filter and alarm exist for route table changes	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
3.14 Ensure a log metric filter and alarm exist for VPC changes	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
4.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs	AWSSecurityHub	Detect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
Recon:EC2/Portscan	AWSWebApplicationFirewall	Protect	La aplicación de conjuntos de reglas de AWSManagedRulesBotControlRuleSet protege contra los bots que ejecutan escaneos en aplicaciones web. https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.htmlgroups-baseline.html	Applying AWSManagedRulesBotControlRuleSet rule sets protects against bots that run scans against web applications. https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.htmlgroups-baseline.html
api-gw-cache-enabled-and-encrypted	AWSConfig	Protect	Para ayudar a proteger los datos en reposo, asegúrese de que el cifrado esté habilitado para la caché de su etapa API Gateway. Debido a que los datos confidenciales se pueden capturar para el método API, habilite el cifrado en reposo para ayudar a proteger esos datos	To help protect data at rest, ensure encryption is enabled for your API Gateway stage’s cache. Because sensitive data can be captured for the API method, enable encryption at rest to help protect that data
Policy:S3/BucketPublicAccessGranted	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketpublicaccessgranted	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketpublicaccessgranted
api-gw-execution-logging-enabled	AWSConfig	Detect	El registro de API Gateway muestra vistas detalladas de los usuarios que accedieron a la API y la forma en que accedieron a la API. Esta información permite la visibilidad de las actividades de los usuarios. Si es deshabilitado, puede deberse a una táctica de Evasión de Defensa	API Gateway logging displays detailed views of users who accessed the API and the way they accessed the API. This insight enables visibility of user activities. If disabled, it may be due to a Defense Evasion tactic
cloudtrail-enabled	AWSConfig	Protect	El registro de eventos de CloudTrail puede ayudar a identificar los usuarios y las cuentas de AWS que llamaron a un servicio de AWS, la dirección IP de origen donde se generaron las llamadas y los tiempos de las llamadas. Si está deshabilitado, puede deberse a una táctica de evasión de defensa	CloudTrail events log can help identify the users and AWS accounts that called an AWS service, the source IP address where the calls generated, and the timings of the calls. If disabled, it may be due to a Defense Evasion tactic
cloud-trail-encryption-enabled	AWSConfig	Protect	Debido a que pueden existir datos confidenciales y para ayudar a proteger los datos en reposo, asegúrese de que el cifrado esté habilitado para sus registros de seguimiento de AWS CloudTrail	Because sensitive data may exist and to help protect data at rest, ensure encryption is enabled for your AWS CloudTrail trails
cloudtrail-s3-dataevents-enabled	AWSConfig	Protect	Habilitar la recopilación de eventos de datos de Simple Storage Service (Amazon S3) ayuda a detectar cualquier actividad anómala. Los detalles incluyen la información de la cuenta de AWS que accedió a un depósito de Amazon S3, la dirección IP y la hora del evento	Enable the collection of Simple Storage Service (Amazon S3) data events helps in detecting any anomalous activity. The details include AWS account information that accessed an Amazon S3 bucket, IP address, and time of event
cloudwatch-log-group-encrypted	AWSConfig	Protect	Para ayudar a proteger los datos confidenciales en reposo, asegúrese de que el cifrado esté habilitado para sus grupos de registro de Amazon CloudWatch	To help protect sensitive data at rest, ensure encryption is enabled for your Amazon CloudWatch Log Groups
cmk-backing-key-rotation-enabled	AWSConfig	Protect	Las claves criptográficas son susceptibles de ser interceptadas y expuestas con el tiempo. Habilite la rotación de claves para asegurarse de que las claves se roten una vez que hayan llegado al final de su período criptográfico. Las claves nuevas tienen un menor tiempo de exposición	Cryptographic keys are susceptible to being intercepted and exposed over time. Enable key rotation to ensure that keys are rotated once they have reached the end of their crypto period. New keys have a shorter exposure time
IOT_ROLE_ALIAS_ALLOWS_ACCESS_TO_UNUSED_SERVICES_CHECK	AWSIOTDeviceDefender	Protect	"Role alias allows access to unused services" puede identificar los alias de rol de AWS IoT que permiten que los dispositivos conectados se autentiquen usando sus certificados y obtengan credenciales de AWS de corta duración de un rol IAM asociado que otorga permisos y privilegios más allá de los necesarios para las funciones de los dispositivos	"Role alias allows access to unused services" can identify AWS IoT role aliases which allow connected devices to authenticate using their certificates and obtain short-lived AWS credentials from an associated IAM role which grant permissions and privileges beyond those necessary to the device´s functions
Policy:IAMUser/S3BucketReplicatedExternally	AmazonMacie	Detect	Detecta la recopilación de datos de en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
Policy:IAMUser/S3BucketSharedExternally	AmazonMacie	Detect	Detecta la recopilación de datos de en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
beanstalk-enhanced-health-reporting-enabled	AWSConfig	Protect	Los informes de estado mejorados de Elastic Beanstalk proporcionan un descriptor de estado para medir la gravedad de los problemas identificados e identificar posibles causas para investigar. Si es deshabilitado, puede deberse a una táctica de Evasión de Defensa	Elastic Beanstalk enhanced health reporting provides a status descriptor to gauge the severity of the identified issues and identify possible causes to investigate. If disabled, it may be due to a Defense Evasion tactic
cloud-trail-log-file-validation-enabled	AWSConfig	Protect	Utilice la validación de archivos de registro de AWS CloudTrail para verificar la integridad de los registros. Esto ayuda a determinar si un archivo de registro se modificó o eliminó después de que CloudTrail lo archivara. Esto hace que sea computacionalmente inviable modificar, eliminar o falsificar registro de CloudTrail sin detección	Utilize AWS CloudTrail log file validation to check the integrity of CloudTrail logs. Log file validation helps determine if a log file was modified or deleted or unchanged after CloudTrail delivered it. This makes it computationally infeasible to modify, delete or forge CloudTrail log files without detection
db-instance-backup-enabled	AWSConfig	Protect	La función de copia de seguridad de Amazon RDS crea copias de seguridad de sus bases de datos y registros de transacciones. Amazon RDS crea automáticamente una instantánea del volumen de almacenamiento de su instancia de base de datos y realiza una copia de seguridad de toda la instancia de base de datos	The backup feature of Amazon RDS creates backups of your databases and transaction logs. Amazon RDS automatically creates a storage volume snapshot of your DB instance, backing up the entire DB instance
dms-replication-not-public 	AWSConfig	Protect	Administre el acceso a la nube de AWS asegurándose de que no se pueda acceder públicamente a las instancias de replicación de DMS. Las instancias de replicación de DMS pueden contener información confidencial y se requiere control de acceso para dichas cuentas	Manage access to the AWS Cloud by ensuring DMS replication instances cannot be publicly accessed. DMS replication instances can contain sensitive information and access control is required for such accounts
dynamodb-in-backup-plan	AWSConfig	Protect	Para ayudar con los procesos de respaldo de datos, asegúrese de que sus tablas de Amazon DynamoDB sean parte de un plan de respaldo de AWS. AWS Backup es un servicio de copia de seguridad completamente administrado con una solución de copia de seguridad basada en políticas https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html	To help with data back-up processes, ensure your Amazon DynamoDB tables are a part of an AWS Backup plan. AWS Backup is a fully managed backup service with a policy-based backup solution https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html
dynamodb-pitr-enabled	AWSConfig	Protect	Habilitar la recuperación de un momento dado (point-in-time recovery ó PITR) de Amazon DynamoDB proporciona copias de seguridad automáticas de los datos de la tabla de DynamoDB https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html	Enabling Amazon DynamoDB point-in-time recovery (PITR) provides automatic backups of your DynamoDB table data https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html
ebs-in-backup-plan	AWSConfig	Protect	Para ayudar con los procesos de respaldo de datos, asegúrese de que sus unidades de almacenamiento en bloque (EBS) sean parte de un plan de respaldo de AWS. AWS Backup es un servicio de copia de seguridad completamente administrado https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html	To help with data back-up processes, ensure your Amazon Elastic Block Store (Amazon EBS) volumes are a part of an AWS Backup plan. AWS Backup is a fully managed backup service with a policy-based backup solution https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html
ebs-snapshot-public-restorable-check	AWSConfig	Protect	Las instantáneas de volumen de EBS pueden contener información confidencial. Las instantáneas de EBS no deberían poder restaurarse públicamente y debería requerirse control de acceso (por IAM)	EBS volume snapshots can contain sensitive information. EBS snapshots should not be publicly restorable and required access control (by IAM)
ec2-instance-no-public-ip	AWSConfig	Protect	Las instancias de Amazon EC2 pueden contener información confidencial. No deberían ser públicamente accesibles las isntancias de Amazon Elastic Compute Cloud (Amazon EC2) y se debería implantar control de acceso	Amazon EC2 instances can contain sensitive information. Amazon Elastic Compute Cloud (Amazon EC2) should not be publicly accessed and access control should be configured
ec2-instance-profile-attached	AWSConfig	Detect	Los perfiles de instancia EC2 transfieren un rol de IAM a una instancia EC2. Adjuntar un perfil de instancia a sus instancias puede ayudar con la administración de permisos y garantizar privilegios mínimos	EC2 instance profiles pass an IAM role to an EC2 instance. Attaching an instance profile to your instances can assist with least privilege and permissions management
ec2-managedinstance-patch-compliance-status-check	AWSConfig	Protect	Habilite esta regla para ayudar con la identificación y documentación de las vulnerabilidades de Amazon Elastic Compute Cloud (Amazon EC2). La regla comprueba si la instancia de Amazon EC2 cumple con los parches en AWS Systems Manager según lo exigen las políticas y los procedimientos de su organización	Enable this rule to help with identification and documentation of Amazon Elastic Compute Cloud (Amazon EC2) vulnerabilities. The rule checks if Amazon EC2 instance patch compliance in AWS Systems Manager as required by your organization’s policies and procedures
ec2-security-group-attached-to-eni	AWSConfig	Detect	Al minimizar la cantidad de grupos de seguridad discretos, las empresas pueden reducir el riesgo de configurar incorrectamente una cuenta. Esta regla ayuda a monitorear grupos de seguridad no utilizados en el inventario	By minimizing the number of discrete security groups, enterprises can reduce the risk of misconfiguring an account. This rule helps monitoring unused security groups in the inventory
ecs-containers-nonprivileged	AWSConfig	Protect	Para ayudar a implementar el principio de privilegios mínimos, las tareas de Amazon Elastic Container Service (Amazon ECS) no deben tener privilegios elevados habilitados. Cuando este parámetro es verdadero, el contenedor recibe privilegios elevados en la instancia del contenedor del host (similar al usuario raíz)	To assist with implementing the principle of least privilege, Amazon Elastic Container Service (Amazon ECS) task definitions should not have elevated privilege enabled. When this parameter is true, the container is given elevated privileges on the host container instance (similar to the root user)
ecs-containers-readonly-access	AWSConfig	Protect	Habilitar el acceso de solo lectura a los contenedores de Amazon Elastic Container Service (ECS) puede ayudar a cumplir con el principio de privilegio mínimo. Esta opción puede reducir los vectores de ataque ya que el sistema de archivos de la instancia del contenedor no se podrá modificar a menos que tenga permisos explícitos de escritura	Enabling read only access to Amazon Elastic Container Service (ECS) containers can assist in adhering to the principal of least privilege. This option can reduces attack vectors as the container instance’s filesystem cannot be modified unless it has explicit read-write permissions
efs-access-point-enforce-root-directory	AWSConfig	Protect	La aplicación de un directorio raíz para un punto de acceso de Amazon Elastic File System (Amazon EFS) ayuda a restringir el acceso a los datos al garantizar que los usuarios del punto de acceso solo puedan acceder a los archivos del subdirectorio especificado	Enforcing a root directory for an Amazon Elastic File System (Amazon EFS) access point helps restrict data access by ensuring that users of the access point can only reach files of the specified subdirectory
efs-encrypted-check	AWSConfig	Protect	Debido a que pueden existir datos confidenciales y para ayudar a proteger los datos en reposo, asegúrese de que el cifrado esté habilitado para su Amazon Elastic File System (EFS)	Because sensitive data can exist and to help protect data at rest, ensure encryption is enabled for your Amazon Elastic File System (EFS)
efs-access-point-enforce-user-identity	AWSConfig	Protect	Para implementar el principio de privilegio mínimo, confirme que usuario forzado esté habilitado para su Amazon Elastic File System. Cuando está habilitado, Amazon EFS reemplaza los ID del cliente NFS por la identidad configurada en el punto de acceso para todas las operaciones del sistema de archivos, y solo otorga acceso a esta identidad	For implementing the principle of least privilege, ensure user enforcement is enabled for your Amazon Elastic File System. When enabled, Amazon EFS replaces the NFS client IDs with the identity configured on the access point for all file system operations, and only grants access to this enforced user identity
elasticsearch-encrypted-at-rest	AWSConfig	Protect	Debido a que pueden existir datos confidenciales y para ayudar a proteger los datos en reposo, asegúrese de que el cifrado esté habilitado para sus dominios de Amazon OpenSearch Service (OpenSearch Service)	Because sensitive data can exist and to help protect data at rest, ensure encryption is enabled for your Amazon OpenSearch Service (OpenSearch Service) domains
elasticsearch-node-to-node-encryption-check	AWSConfig	Detect	Asegúrese de que el cifrado de nodo a nodo para Amazon OpenSearch Service esté habilitado. El cifrado de nodo a nodo permite el cifrado TLS 1.2 para todas las comunicaciones dentro de Amazon Virtual Private Cloud (Amazon VPC). Debido a que pueden existir datos confidenciales, habilite el cifrado en tránsito para ayudar a proteger esos datos	Ensure node-to-node encryption for Amazon OpenSearch Service is enabled. Node-to-node encryption enables TLS 1.2 encryption for all communications within the Amazon Virtual Private Cloud (Amazon VPC). Because sensitive data can exist, enable encryption in transit to help protect that data
elb-tls-https-listeners-only	AWSConfig	Detect	Asegúrese de que sus Elastic Load Balancers (ELBs) están configurados con escuchas SSL o HTTPS. Dado que pueden existir datos sensibles, habilite el cifrado en tránsito para ayudar a proteger esos datos	Ensure that your Elastic Load Balancers (ELBs) are configured with SSL or HTTPS listeners. Because sensitive data can exist, enable encryption in transit to help protect that data
elb-deletion-protection-enabled	AWSConfig	Protect	Esta regla garantiza que Elastic Load Balancing tenga activada la protección contra borrado. Utilice esta función para evitar que su balanceador de carga se elimine de forma accidental o maliciosa, lo que puede provocar la pérdida de disponibilidad de sus aplicaciones	This rule ensures that Elastic Load Balancing has deletion protection enabled. Use this feature to prevent your load balancer from being accidentally or maliciously deleted, which can lead to loss of availability for your applications
elb-acm-certificate-required	AWSConfig	Detect	Dado que pueden existir datos sensibles y para ayudar a proteger los datos en tránsito, asegúrese de que el cifrado está habilitado para su Elastic Load Balancing. Utilice AWS Certificate Manager para administrar, aprovisionar e implementar certificados SSL/TLS públicos y privados con servicios de AWS y recursos internos.	Because sensitive data can exist and to help protect data at transit, ensure encryption is enabled for your Elastic Load Balancing. Use AWS Certificate Manager to manage, provision and deploy public and private SSL/TLS certificates with AWS services and internal resources
elb-cross-zone-load-balancing-enabled	AWSConfig	Protect	Habilite el equilibrio de carga entre zonas para sus Elastic Load Balancers (ELBs) para ayudar a mantener una capacidad y disponibilidad adecuadas. El equilibrio de carga mejora la capacidad de su aplicación para manejar la pérdida de una o más instancias	Enable cross-zone load balancing for your Elastic Load Balancers (ELBs) to help maintain adequate capacity and availability. The cross-zone load balancing improves your application´s ability to handle the loss of one or more instances
iam-user-group-membership-check	AWSConfig	Detect	AWS Identity and Access Management (IAM) puede ayudarle a restringir los permisos de acceso y las autorizaciones, garantizando que los usuarios de IAM sean miembros de al menos un grupo. Permitir a los usuarios más privilegios de los necesarios para completar una tarea puede violar el principio de mínimo privilegio y la separación de funciones	AWS Identity and Access Management (IAM) can help you restrict access permissions and authorizations, by ensuring IAM users are members of at least one group. Allowing users more privileges than needed to complete a task may violate the principle of least privilege and separation of duties
iam-policy-no-statements-with-admin-access	AWSConfig	Detect	AWS Identity and Access Management puede ayudarle a incorporar los principios de mínimo privilegio y separación de funciones con los permisos y autorizaciones de acceso, restringiendo que las políticas contengan "Efecto": "Permitir" con "Acción": "*" sobre "Resource": "*"	AWS Identity and Access Management can help you incorporate the principles of least privilege and separation of duties with access permissions and authorizations, restricting policies from containing "Effect": "Allow" with "Action": "*" over "Resource": "*"
iam-policy-no-statements-with-full-access	AWSConfig	Detect	Asegúrese de que las acciones de IAM estén restringidas sólo a las acciones necesarias. Permitir que los usuarios tengan más privilegios de los necesarios para completar una tarea puede violar el principio de mínimo privilegio y la separación de funciones	Ensure IAM Actions are restricted to only those actions that are needed. Allowing users to have more privileges than needed to complete a task may violate the principle of least privilege and separation of duties
emr-master-no-public-ip	AWSConfig	Protect	Administre el acceso a la nube de AWS garantizando que no se pueda acceder públicamente a los nodos maestros de clústeres de Amazon EMR. Los nodos maestros de clústeres de Amazon EMR pueden contener información sensible y se requiere un control de acceso para dichas cuentas	Manage access to the AWS Cloud by ensuring Amazon EMR cluster master nodes cannot be publicly accessed. Amazon EMR cluster master nodes can contain sensitive information and access control is required for such accounts
encrypted-volumes	AWSConfig	Protect	Debido a que pueden existir datos sensibles y para ayudar a proteger los datos en reposo, asegúrese de que el cifrado está habilitado para sus volúmenes de Amazon Elastic Block Store (Amazon EBS)	Because sensitive data can exist and to help protect data at rest, ensure encryption is enabled for your Amazon Elastic Block Store (Amazon EBS) volumes
elbv2-acm-certificate-required	AWSConfig	Protect	Dado que pueden existir datos sensibles y para ayudar a proteger los datos en tránsito, asegúrese de que el cifrado está habilitado para su Elastic Load Balancing. Utilice AWS Certificate Manager para administrar, aprovisionar e implementar certificados SSL/TLS públicos y privados con servicios de AWS y recursos internos.	Because sensitive data can exist and to help protect data at transit, ensure encryption is enabled for your Elastic Load Balancing. Use AWS Certificate Manager to manage, provision and deploy public and private SSL/TLS certificates with AWS services and internal resources
emr-kerberos-enabled	AWSConfig	Protect	Los permisos y autorizaciones de acceso se pueden administrar e incorporar con los principios de mínimo privilegio y separación de funciones, habilitando Kerberos para los clústeres de Amazon EMR	The access permissions and authorizations can be managed and incorporated with the principles of least privilege and separation of duties, by enabling Kerberos for Amazon EMR clusters
iam-password-policy	AWSConfig	Protect	Una política de contraseñas estricta fortalece contra intentos de acceso no autorizado. Esta regla le permite establecer requireUppercaseCharacters, RequireLowercaseCharacters, RequireSymbols, RequireNumbers, MinimumPasswordLength (14), PasswordReusePrevention (24) y MaxPasswordAge (90) para su política de contraseñas de IAM	A strict password policy strengthens against unauthorized access attempts. This rule allows you to set RequireUppercaseCharacters, RequireLowercaseCharacters, RequireSymbols, RequireNumbers, MinimumPasswordLength (14), PasswordReusePrevention (24), and MaxPasswordAge (90) for your IAM Password Policy
lambda-concurrency-check	AWSConfig	Protect	Para evitar tácticas de Impacto o Ejecución, puede basar la cantidad de solicitudes que su función puede atender en un momento dado al establecer los límites alto y bajo de simultaneidad de la función Lambda	To prevent Impact or Execution tactics, you can baselining the number of requests that your function can serving at any given time by establishing Lambda function´s concurrency high and low limits
rds-snapshots-public-prohibited	AWSConfig	Protect	Administre el acceso a los recursos en la nube de AWS garantizando que las instancias de Amazon Relational Database Service (Amazon RDS) no sean públicas. Las instancias de bases de datos de Amazon RDS pueden contener información y principios sensibles y se requiere un control de acceso para dichas cuentas	Manage access to resources in the AWS Cloud by ensuring that Amazon Relational Database Service (Amazon RDS) instances are not public. Amazon RDS database instances can contain sensitive information and principles and access control is required for such accounts
rds-storage-encrypted	AWSConfig	Protect	Para ayudar a proteger los datos en reposo, asegúrese de que el cifrado está habilitado para sus instancias de Amazon Relational Database Service (Amazon RDS). Dado que los datos sensibles pueden existir en reposo en las instancias de Amazon RDS, habilite el cifrado en reposo para ayudar a proteger esos datos	To help protect data at rest, ensure that encryption is enabled for your Amazon Relational Database Service (Amazon RDS) instances. Because sensitive data can exist at rest in Amazon RDS instances, enable encryption at rest to help protect that data
rds-instance-deletion-protection-enabled	AWSConfig	Protect	Asegúrese de que las instancias de Amazon Relational Database Service (Amazon RDS) tengan habilitada la protección contra el borrado. Utilice la protección contra la eliminación para evitar que sus instancias de Amazon RDS se eliminen de forma accidental o maliciosa, lo que puede provocar la pérdida de disponibilidad de sus aplicaciones	Ensure Amazon Relational Database Service (Amazon RDS) instances have deletion protection enabled. Use deletion protection to prevent your Amazon RDS instances from being accidentally or maliciously deleted, which can lead to loss of availability for your applications
rds-automatic-minor-version-upgrade-enabled	AWSConfig	Protect	La activación de las actualizaciones automáticas de versiones menores para Amazon Relational Database Service (RDS) garantiza la instalación de las últimas actualizaciones de versiones menores del sistema de administración de bases de datos relacionales (RDBMS), que pueden incluir parches de seguridad y correcciones de errores	Enabling automatic minor version upgrades for Amazon Relational Database Service (RDS) ensures the latest minor version updates to the Relational Database Management System (RDBMS) are installed, which may include security patches and bug fixes
rds-enhanced-monitoring-enabled	AWSConfig	Detect	Habilite Amazon Relational Database Service (Amazon RDS) para ayudar a monitorizar la disponibilidad de Amazon RDS. Esto proporciona una visibilidad detallada de la salud de sus instancias de base de datos de Amazon RDS	Enable Amazon Relational Database Service (Amazon RDS) to help monitor Amazon RDS availability. This provides detailed visibility into the health of your Amazon RDS database instances
lambda-function-public-access-prohibited	AWSConfig	Protect	Gestione el acceso a los recursos en la nube de AWS garantizando que no se pueda acceder públicamente a las funciones de AWS Lambda. El acceso público puede conducir potencialmente a la degradación de la disponibilidad de los recursos	Manage access to resources in the AWS Cloud by ensuring AWS Lambda functions cannot be publicly accessed. Public access can potentially lead to degradation of availability of resources
rds-multi-az-support	AWSConfig	Protect	La compatibilidad con Multi-AZ en Amazon Relational Database Service (Amazon RDS) proporciona disponibilidad y durabilidad mejoradas para las instancias de bases de datos. En caso de falla de la infraestructura, Amazon RDS realiza una conmutación por error automática para que pueda reanudar las operaciones de la base de datos	Multi-AZ support in Amazon Relational Database Service (Amazon RDS) provides enhanced availability and durability for database instances. In case of an infrastructure failure, Amazon RDS performs an automatic failover to the standby so that you can resume database operations as soon as the failover is complete
s3-bucket-default-lock-enabled	AWSConfig	Protect	Asegúrese de que su cubo de Amazon Simple Storage Service (Amazon S3) tiene activado el bloqueo, por defecto. Dado que los datos sensibles pueden existir en reposo en los buckets de S3, aplique bloqueos de objetos en reposo para ayudar a proteger esos datos	Ensure that your Amazon Simple Storage Service (Amazon S3) bucket has lock enabled, by default. Because sensitive data can exist at rest in S3 buckets, enforce object locks at rest to help protect that data
root-account-hardware-mfa-enabled	AWSConfig	Protect	Asegúrese de que la MFA de hardware esté habilitada para el usuario raíz. El usuario raíz es el usuario con más privilegios en una cuenta de AWS. La MFA añade una capa adicional de protección para el nombre de usuario y la contraseña. Al requerir MFA para el usuario raíz, puede reducir los incidentes de cuentas AWS comprometidas	Manage access to resources in the AWS Cloud by ensuring hardware MFA is enabled for the root user. The root user is the most privileged user in an AWS account. The MFA adds an extra layer of protection for a user name and password. By requiring MFA for the root user, you can reduce the incidents of compromised AWS accounts
redshift-require-tls-ssl	AWSConfig	Protect	Asegúrese de que sus clústeres de Amazon Redshift requieren el cifrado TLS/SSL para conectarse a los clientes de SQL. Dado que pueden existir datos sensibles, habilite el cifrado en tránsito para ayudar a proteger esos datos	Ensure that your Amazon Redshift clusters require TLS/SSL encryption to connect to SQL clients. Because sensitive data can exist, enable encryption in transit to help protect that data
redshift-enhanced-vpc-routing-enabled	AWSConfig	Detect	El enrutamiento mejorado por VPC obliga a que todo el tráfico de COPY y UNLOAD entre el clúster y los repositorios de datos pase por su VPC de Amazon. Podrá utilizar las características de la VPC, como los grupos de seguridad y las listas de control de acceso a la red, para proteger el tráfico	Enhanced VPC routing forces all COPY and UNLOAD traffic between the cluster and data repositories to go through your Amazon VPC. You can then use VPC features such as security groups and network access control lists to secure network traffic. You can also use VPC flow logs to monitor network traffic
opensearch-access-control-enabled	AWSConfig	Protect	Asegúrese de que el control de acceso de grano-fino está habilitado en sus dominios de Amazon OpenSearch Service. El control de acceso de grano-fino proporciona mecanismos de autorización mejorados para lograr el acceso con menos privilegios a los dominios de Amazon OpenSearch Service	Ensure fine-grained access control is enabled on your Amazon OpenSearch Service domains. Fine-grained access control provides enhanced authorization mechanisms to achieve least-privileged access to Amazon OpenSearch Service domains
redshift-cluster-configuration-check	AWSConfig	Protect	Para proteger los datos en reposo, el cifrado debe estar habilitado para sus clústeres de Amazon Redshift. El registro de auditoría debe estar habilitado para proporcionar información sobre las conexiones y actividades de usuarios en la base de datos. Esta regla requiere que se establezca valores para clusterDbEncrypted:TRUE y loggingEnabled:TRUE	To protect data at rest, ensure that encryption is enabled for your Amazon Redshift clusters. The audit logging should be enabled to provide information about connections and user activities in the database. This rule requires that a value is set for clusterDbEncrypted (Config Default : TRUE), and loggingEnabled (Config Default: TRUE)
mfa-enabled-for-iam-console-access	AWSConfig	Protect	Gestione el acceso a los recursos en la nube de AWS asegurándose de que MFA esté habilitado para todos los usuarios de AWS IAM que tengan una contraseña de consola. Al exigir MFA a los usuarios de IAM, puede reducir los incidentes de cuentas comprometidas y evitar que usuarios no autorizados accedan a datos confidenciales	Manage access to resources in the AWS Cloud by ensuring that MFA is enabled for all AWS Identity and Access Management users that have a console password. By requiring MFA for IAM users, you can reduce incidents of compromised accounts and keep sensitive data from being accessed by unauthorized users
sagemaker-notebook-no-direct-internet-access	AWSConfig	Protect	Administre el acceso a los recursos en la nube de AWS asegurándose de que los portátiles de Amazon SageMaker no permitan el acceso directo a Internet. Al impedir el acceso directo a Internet, puede evitar que usuarios no autorizados accedan a los datos confidenciales	Manage access to resources in the AWS Cloud by ensuring that Amazon SageMaker notebooks do not allow direct internet access. By preventing direct internet access, you can keep sensitive data from being accessed by unauthorized users
s3-bucket-ssl-requests-only	AWSConfig	Detect	Para ayudar a proteger los datos en tránsito, asegúrese de que sus buckets de Amazon Simple Storage Service (Amazon S3) requieren que las solicitudes utilicen Secure Socket Layer (SSL). Dado que pueden existir datos sensibles, habilite el cifrado en tránsito para ayudar a proteger esos datos	To help protect data in transit, ensure that your Amazon Simple Storage Service (Amazon S3) buckets require requests to use Secure Socket Layer (SSL). Because sensitive data can exist, enable encryption in transit to help protect that data
s3-bucket-replication-enabled	AWSConfig	Protect	Amazon Simple Storage Service (Amazon S3) Cross-Region Replication (CRR) permite mantener una capacidad y disponibilidad adecuadas. CRR permite la copia automática y asíncrona de objetos entre los buckets de Amazon S3 para ayudar a garantizar que se mantenga la disponibilidad de los datos	Amazon Simple Storage Service (Amazon S3) Cross-Region Replication (CRR) supports maintaining adequate capacity and availability. CRR enables automatic, asynchronous copying of objects across Amazon S3 buckets to help ensure that data availability is maintained
s3-bucket-server-side-encryption-enabled	AWSConfig	Protect	Para ayudar a proteger los datos en reposo, asegúrese de que el cifrado está habilitado para sus buckets de Amazon Simple Storage Service (Amazon S3). Dado que los datos sensibles pueden existir en reposo en los buckets de Amazon S3, habilite el cifrado para ayudar a proteger esos datos	To help protect data at rest, ensure encryption is enabled for your Amazon Simple Storage Service (Amazon S3) buckets. Because sensitive data can exist at rest in Amazon S3 buckets, enable encryption to help protect that data
s3-account-level-public-access-blocks-periodic	AWSConfig	Protect	Gestione el acceso a los recursos en la nube de AWS garantizando que no se pueda acceder públicamente a los buckets de Amazon S3. Esta regla ayuda a mantener los datos sensibles a salvo de usuarios remotos no autorizados, comprobando que se han establecido los parámetros ignorePublicAcls, blockPublicPolicy, blockPublicAcls y restrictPublicBuckets	Manage access to resources in the AWS Cloud by ensuring that Amazon Simple Storage Service buckets cannot be publicly accessed. This rule helps keeping sensitive data safe from unauthorized remote users. This rule allows you to optionally set the ignorePublicAcls, blockPublicPolicy, blockPublicAcls, and restrictPublicBuckets parameters
subnet-auto-assign-public-ip-disabled	AWSConfig	Detect	Las instancias de Amazon Elastic Compute Cloud (EC2) no deberían ser accesibles públicamente. Deshabilite el atributo "asignar automáticamente una dirección IP pública" en la creación de subredes para evitar que a las instancias que se desplieguen en dichas subredes se les asigne una dirección IP pública a su interfaz de red	Amazon Elastic Compute Cloud (EC2) instances should not be publicly accessible. Disable the "automatically assign a public IP address" attribute on subnet creation to prevent instances that are deployed in those subnets from being assigned a public IP address to their network interface
s3-bucket-logging-enabled 	AWSConfig	Detect	Los registros de acceso Amazon S3 proporcionan un método para monitorizar la red en busca de posibles eventos de ciberseguridad. Los detalles de los registros incluyen el solicitante, el nombre del bucket, la hora, la acción de la solicitud, el estado de la respuesta y un código de error, si es relevante	Amazon Simple Storage Service server access logging provides a method to monitor the network for potential cybersecurity events. Each access log record provides details about a single access request. The details include the requester, bucket name, request time, request action, response status, and an error code, if relevant
elb-tls-https-listeners-only	AWSCloudWatch	Protect	AWS CloudWatch utiliza conexiones TLS/SSL para comunicarse con otros recursos de AWS	AWS CloudWatch uses TLS/SSL connections to communicate with other AWS resources
iam-root-access-key-check	AWSConfig	Protect	El usuario raíz no debe tener claves de acceso adjuntas a su rol de AWS Identity and Access Management (IAM). Asegúrese de que se eliminen las claves de acceso raíz. En su lugar, cree y utilice cuentas de AWS basadas en roles para ayudar a incorporar el principio de funcionalidad mínima	The root user should not have access keys attached to their AWS Identity and Access Management (IAM) role. Ensure that the root access keys are deleted. Instead, create and use role-based AWS accounts to help to incorporate the principle of least functionality
alb-http-drop-invalid-header-enabled	AWSConfig	Protect	Asegúrese de que sus Balanceadores (ELB) estén configurados para descartar encabezados http. Debido a que pueden existir datos confidenciales, habilite el cifrado en tránsito para ayudar a proteger esos datos	Ensure that your Elastic Load Balancers (ELB) are configured to drop http headers. Because sensitive data can exist, enable encryption in transit to help protect that data
alb-waf-enabled	AWSConfig	Protect	Asegúrese de que AWS WAF esté habilitado en sus Balanceadores (ELB) para ayudar a proteger las aplicaciones web. Un WAF ayuda a proteger sus aplicaciones web o API contra vulnerabilidades web comunes. Estos exploits web pueden afectar la disponibilidad, comprometer la seguridad o consumir recursos excesivos dentro de su entorno	Ensure AWS WAF is enabled on Elastic Load Balancers (ELB) to help protect web applications. A WAF helps to protect your web applications or APIs against common web exploits. These web exploits may affect availability, compromise security, or consume excessive resources within your environment
wafv2-logging-enabled	AWSConfig	Protect	Para ayudar con el registro y la monitorización dentro de su entorno, habilite el registro de AWS WAF en las ACL web regionales y globales. Los registros registran la hora a la que AWS WAF recibió la solicitud de su recurso de AWS, la información sobre la solicitud y una acción para la regla con la que coincidió cada solicitud	To help with logging and monitoring within your environment, enable AWS WAF logging on regional and global web ACLs. The logs record the time that AWS WAF received the request from your AWS resource, information about the request, and an action for the rule that each request matched
elasticsearch-in-vpc-only	AWSConfig	Detect	Un dominio de OpenSearch Service dentro de una VPC de Amazon permite la comunicación segura entre OpenSearch Service y otros servicios dentro de la VPC de Amazon sin necesidad de una puerta de enlace a Internet, un dispositivo NAT o una conexión VPN	An OpenSearch Service domain within an Amazon VPC enables secure communication between OpenSearch Service and other services within the Amazon VPC without the need for an internet gateway, NAT device, or VPN connection
vpc-flow-logs-enabled	AWSConfig	Protect	Habilite los registros de flujo de VPC para proporcionar registros detallados de información sobre el tráfico de IP (incluido el origen, el destino y el protocolo) que va y viene de las interfaces de red en su Amazon Virtual Private Cloud (Amazon VPC)	Enable the VPC flow logs to provide detailed records for information about the IP traffic (including the source, destination, and protocol) going to and from network interfaces in your Amazon Virtual Private Cloud (Amazon VPC)
s3-bucket-acl-prohibited	AWSConfig	Protect	Esta regla comprueba si se utilizan listas de control de acceso para controlar el acceso a los buckets de Amazon S3. En lugar de las ACL, es una práctica recomendada utilizar las políticas de IAM o las políticas de los buckets de S3 para administrar más fácilmente el acceso a sus buckets de S3	This rule checks to see if Access Control Lists are used to for access control on Amazon S3 Buckets. Instead of ACLs, it is a best practice to use IAM policies or S3 bucket policies to more easily manage access to your S3 buckets
s3-bucket-versioning-enabled	AWSConfig	Protect	El versionado en buckets Amazon S3 ayuda a mantener múltiples variantes de un objeto en el mismo cubo de Amazon S3. Utilice el versionado para conservar, recuperar y restaurar cada versión de cada objeto almacenado en su bucket. El control de versiones le ayuda a recuperarse fácilmente de acciones involuntarias y fallos de aplicaciones	Amazon Simple Storage Service (Amazon S3) bucket versioning helps keep multiple variants of an object in the same Amazon S3 bucket. Use versioning to preserve, retrieve, and restore every version of every object stored in your Amazon S3 bucket. Versioning helps you to easily recover from unintended user actions and application failures
PenTest:IAMUser/PentooLinux	AmazonGuardDuty	Detect	Marca una instancia en la que hay indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-pentoolinux	Flags an instance where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-pentoolinux
Exfiltration:IAMUser/AnomalousBehavior	AWSOrganizations	Protect	Mitigación: mediante implementación de políticas de control de servicios	Mitigation: implementing service control policies
iam-password-policy	AmazonCognito	Protect	La capacidad MFA de Amazon Cognito brinda una protección significativa contra compromisos de contraseñas	Amazon Cognito MFA capability provides significant protection against password compromises
3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
AWS principals with suspicious access key activity	AWSSecurityHub	Detect	Insights: detecta actividad sospechosa de cuentas de AWS que podría indicar que un adversario está aprovechando cuentas válidas	Insights: detects suspicious activity by AWS accounts which could indicate valid accounts being leveraged by an adversary
AWS resources with unauthorized access attempts	AWSSecurityHub	Detect	Insights: detecta actividad sospechosa de cuentas de AWS que podría indicar que un adversario está aprovechando cuentas válidas	Insights: detects suspicious activity by AWS accounts which could indicate valid accounts being leveraged by an adversary
Credentials that may have leaked	AWSSecurityHub	Detect	Insights: detecta actividad sospechosa de cuentas de AWS que podría indicar que un adversario está aprovechando cuentas válidas	Insights: detects suspicious activity by AWS accounts which could indicate valid accounts being leveraged by an adversary
iam-user-mfa-enabled	AWSIAM	Protect	El uso de autenticación multi-factor, políticas de contraseñas seguras y credenciales rotativas puede mitigar los ataques de fuerza bruta	Enforcing multi-factor authentication, strong password policies, and rotating credentials may mitigate brute force attacks
encrypted-volumes	AWSCloudHSM	Protect	Este servicio proporciona una alternativa más segura al almacenamiento de claves de cifrado en el sistema de archivos	This service provides a more secure alternative to storing encryption keys in the file system
s3-bucket-versioning-enabled	AWSS3	Protect	Puede proteger contra la destrucción de datos mediante la aplicación de varias mejores prácticas. Autenticación multifactor habilitada para operaciones de eliminación, control de versiones, bloqueo de objetos de S3, replicación entre regiones de S3	May protect against data destruction through application of several best practices. Multi-factor authentication enabled for delete operations, Versioning, S3 Object Lock, S3 Cross Region Replication
SensitiveData:S3Object/Multiple	AmazonMacie	Protect	Detecta la recopilación de datos confidenciales en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of sensitive data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
UnauthorizedAccess:EC2/MetadataDNSRebind	AmazonInspector	Protect	Amazon Inspector puede detectar vulnerabilidades conocidas en varios puntos finales de Windows y Linux	Amazon Inspector can detect known vulnerabilities on various Windows and Linux endpoints
rds-automatic-minor-version-upgrade-enabled	AWSRDS	Protect	Verifique que la aplicación automática de parches esté habilitada: rds-automatic-minor-version-upgrade-enabled	Verify that automatic patching is enabled: rds-automatic-minor-version-upgrade-enabled
Trojan:EC2/DriveBySourceTraffic!DNS	AWSWebApplicationFirewall	Protect	La aplicación de conjuntos de reglas AWSManagedRulesCommonRuleSet protege contra bots que ejecutan escaneos en aplicaciones web. https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html	Applying AWSManagedRulesCommonRuleSet rule sets protects against bots that run scans against web applications. https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
EC2 instances that have missing security patches for important vulnerabilities	AWSSecurityHub	Protect	Insights: AWS Security Hub informa sobre instancias EC2 a las que les faltan parches de seguridad para vulnerabilidades que podrían permitir que un adversario aproveche las vulnerabilidades	Insights: AWS Security Hub reports on EC2 instances that are missing security patches for vulnerabilities which could enable an adversary to exploit vulnerabilities
UnauthorizedAccess:EC2/MetadataDNSRebind	AWSWebApplicationFirewall	Protect	La aplicación de conjuntos de reglas AWSManagedRulesCommonRuleSet protege contra bots que ejecutan escaneos en aplicaciones web. https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html	Applying AWSManagedRulesCommonRuleSet rule sets protects against bots that run scans against web applications. https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
AUTHENTICATED_COGNITO_ROLE_OVERLY_PERMISSIVE_CHECK	AWSIOTDeviceDefender	Protect	La verificación "Authenticated Cognito role overly permissive" puede identificar políticas que otorgan privilegios excesivos	"Authenticated Cognito role overly permissive" audit check can identify policies which grant excessive privileges.
CredentialAccess:IAMUser/AnomalousBehavior	AmazonCognito	Protect	Amazon Cognito tiene la capacidad de alertar y bloquear cuentas en las que se descubrió que las credenciales estaban comprometidas en otro lugar (protección de credenciales comprometidas)	Amazon Cognito has the ability to alert and block accounts where credentials were found to be compromised elsewhere (compromised credential protection)
Discovery:IAMUser/AnomalousBehavior	AWSIAM	Protect	La herramienta Access Analyzer puede detectar cuándo se le ha otorgado acceso a una entidad externa a los recursos de la nube mediante el uso de políticas de acceso	The Access Analyzer tool may detect when an external entity has been granted access to cloud resources through use of access policies
Recon:EC2/PortProbeUnprotectedPort	AmazonGuardDuty	Detect	There is an attempt to get a list of services running on a remote host. Remediation/recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portprobeunprotectedport	There is an attempt to get a list of services running on a remote host. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portprobeunprotectedport
UnauthorizedAccess:IAMUser/MaliciousIPCaller	AmazonGuardDuty	Detect	Marca una instancia en la que hay indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-maliciousipcaller	Flags an instance where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-maliciousipcaller
UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom	AmazonGuardDuty	Detect	Marca una instancia en la que hay indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-maliciousipcaller	Flags an instance where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-maliciousipcaller
UnauthorizedAccess:IAMUser/TorIPCaller	AmazonGuardDuty	Detect	Marca una instancia en la que hay indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-toripcaller	Flags an instance where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-toripcaller
IOT_POLICY_OVERLY_PERMISSIVE_CHECK	AWSIOTDeviceDefender	Protect	La verificación "AWS IoT policies overly permissive" puede identificar las políticas de AWS IoT que otorgan privilegios excesivos	"AWS IoT policies overly permissive" audit check can identify AWS IoT policies which grant excessive privileges.
CONFLICTING_CLIENT_IDS_CHECK	AWSIOTDeviceDefender	Detect	"Conflicting MQTT client IDs" sugiere que un adversario puede estar usando clones de dispositivos comprometidos para aprovechar su acceso	"Conflicting MQTT client IDs" suggest that an adversary may be using clones of compromised devices to leverage their access.
aws:num-connection-attempts	AWSIOTDeviceDefender	Detect	Recuentos altos de "Connection attempts" pueden indicar que un dispositivo comprometido se está conectando y desconectando de AWS IoT mediante el acceso asociado del dispositivo	"Connection attempts" High counts, may indicate that a compromised device is connecting and disconnecting from AWS IoT using the device's associated access.
aws:num-disconnects	AWSIOTDeviceDefender	Detect	Recuentos altos de "Disconnects" pueden indicar que un dispositivo comprometido se está conectando y desconectando de AWS IoT mediante el acceso asociado del dispositivo	"Disconnects" High counts, may indicate that a compromised device is connecting and disconnecting from AWS IoT using the device's associated access.
IOT_ROLE_ALIAS_OVERLY_PERMISSIVE_CHECK	AWSIOTDeviceDefender	Protect	"Role alias overly permissive" puede identificar los alias de rol de AWS IoT que permiten que los dispositivos conectados se autentiquen usando sus certificados y obtengan credenciales de AWS de corta duración de un rol de IAM asociado que otorga permisos y privilegios más allá de los necesarios para las funciones de los dispositivos	"Role alias overly permissive" can identify AWS IoT role aliases which allow connected devices to authenticate using their certificates and obtain short-lived AWS credentials from an associated IAM role which grant permissions and privileges beyond those necessary to the devices' functions.
Impact:IAMUser/AnomalousBehavior	AWSSecretsManager	Protect	Mitigación: reemplazar tokens de llamada API autenticados y cifrados a AWS Secrets Manager	Mitigation: replacing those tokens with authenticated and encrypted API calls to AWS Secrets Manager
[PCI.CW.1] A log metric filter and alarm should exist for usage of the "root" user	AWSSecurityHub	Protect	AWS PCI-DSS security standard: esta herramienta ayudaría a detectar el mal uso de cuentas válidas	AWS PCI-DSS security standard: this tool would help towards detecting the misuse of valid accounts
aws:source-ip-address	AWSIOTDeviceDefender	Detect	Los valores de "Source IP" fuera de los rangos de direcciones IP esperados pueden sugerir que se ha robado un dispositivo	"Source IP" values outside of expected IP address ranges may suggest that a device has been stolen.
UNAUTHENTICATED_COGNITO_ROLE_OVERLY_PERMISSIVE_CHECK	AWSIOTDeviceDefender	Protect	La verificación de "Unauthenticated Cognito role verly permissive" puede identificar políticas que otorgan privilegios excesivos	"Unauthenticated Cognito role verly permissive" audit check can identify policies which grant excessive privileges.
UnauthorizedAccess:S3/MaliciousIPCaller.Custom	AmazonGuardDuty	Detect	Los adversarios podrían cifrar o destruir datos y archivos en sistemas específicos para interrumpir la disponibilidad de sistemas, servicios y recursos de red. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#unauthorizedaccess-s3-maliciousipcallercustom	Adversaries may encrypt or destroy data and files on specific systems to interrupt availability to systems, services, and network resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#unauthorizedaccess-s3-maliciousipcallercustom
Stealth:IAMUser/PasswordPolicyChange	AmazonGuardDuty	Detect	Una instancia EC2 puede verse involucrada en un ataque de fuerza bruta destinado a obtener contraseñas. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-passwordpolicychange	An EC2 instance may be involved in a brute force attack aimed at obtaining passwords. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-passwordpolicychange
aws:message-byte-size	AWSIOTDeviceDefender	Detect	Los valores de "Message size" fuera de las normas esperadas pueden indicar que los dispositivos están enviando y/o recibiendo tráfico no estándar	"Message size" values outside of expected norms may indicate that devices are sending and/or receiving non-standard traffic.
CryptoCurrency:EC2/BitcoinTool.B	AmazonGuardDuty	Detect	Los adversarios pueden aprovechar los recursos de los sistemas cooptados para resolver problemas intensivos en recursos que pueden afectar la disponibilidad del sistema y/o del servicio alojado. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolb	Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolb
rds-instance-deletion-protection-enabled	AWSRDS	Protect	AWS RDS proporciona protección contra eliminación que evita que cualquier usuario elimine una instancia de base de datos	AWS RDS provides deletion protection which prevents any user from deleting a database instance
Policy:IAMUser/S3BlockPublicAccessDisabled	AmazonMacie	Detect	Detecta la recopilación de datos de en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
Policy:IAMUser/S3BucketEncryptionDisabled	AmazonMacie	Detect	Detecta la recopilación de datos de en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
Policy:IAMUser/S3BucketPublic	AmazonMacie	Detect	Detecta la recopilación de datos de en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
SensitiveData:S3Object/Credentials	AmazonMacie	Protect	Detecta la recopilación de datos confidenciales en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of sensitive data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
SensitiveData:S3Object/CustomIdentifier	AmazonMacie	Protect	Detecta la recopilación de datos confidenciales en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of sensitive data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
SensitiveData:S3Object/Financial	AmazonMacie	Protect	Detecta la recopilación de datos confidenciales en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of sensitive data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
SensitiveData:S3Object/Personal	AmazonMacie	Protect	Detecta la recopilación de datos confidenciales en bucket S3. https://docs.aws.amazon.com/macie/latest/user/findings-types.html	Detects the collection of sensitive data from S3 buckets. https://docs.aws.amazon.com/macie/latest/user/findings-types.html
Exfiltration:S3/MaliciousIPCaller	AmazonGuardDuty	Detect	Detectadas interacciones potencialmente maliciosas con S3 que pueden comprometer cualquier archivo de credenciales almacenado en S3. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#exfiltration-s3-maliciousipcaller	Potentially malicious interactions with S3 which may lead to the compromise of any credential files stored in S3. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#exfiltration-s3-maliciousipcaller
Recon:IAMUser/TorIPCaller	AmazonGuardDuty	Detect	Detectado intento de descubrir información sobre recursos en la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-toripcaller	Attempt to discover information about resources on the account. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-toripcaller
LOGGING_DISABLED_CHECK	AWSIOTDeviceDefender	Detect	"Logging disabled" puede identificar cambios potencialmente maliciosos en los registros de AWS IoT	"Logging disabled" can identify potentially malicious changes to AWS IoT logs.
vpc-sg-open-only-to-authorized-ports	AWSConfig	Detect	No restringir el acceso a los puertos a las fuentes de confianza puede dar lugar a ataques contra la disponibilidad, integridad y confidencialidad de los sistemas. Al restringir el acceso a los recursos de un grupo de seguridad desde Internet (0.0.0.0/0) se puede controlar el acceso remoto a los sistemas internos	Not restricting access on ports to trusted sources can lead to attacks against the availability, integrity and confidentiality of systems. By restricting access to resources within a security group from the internet (0.0.0.0/0) remote access can be controlled to internal systems
efs-in-backup-plan	AWSConfig	Protect	Para ayudar con los procesos de respaldo de datos, asegúrese de que sus sistemas de fichero de Amazon Elastic File System sean parte de un plan de respaldo de AWS. AWS Backup es un servicio de copia de seguridad completamente administrado https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html	To help with data back-up processes, ensure your Amazon Elastic File System file systems are a part of an AWS Backup plan. AWS Backup is a fully managed backup service with a policy-based backup solution https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html
mfa-enabled-for-iam-console-access	AWSOrganizations	Protect	Mitigación: puede proteger contra el descubrimiento de cuentas en la nube al segmentar las cuentas en unidades organizativas separadas	Mitigation: may protect against cloud account discovery by segmenting accounts into separate organizational units
3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes 	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
3.10 Ensure a log metric filter and alarm exist for security group changes	AWSSecurityHub	Protect	AWS Foundations CIS Benchmark: esta herramienta ayudaría a detectar cambios en los servicios clave de AWS	AWS Foundations CIS Benchmark: this tool wwould help towards detecting changes to key AWS services
S3 buckets with public write or read permissions	AWSSecurityHub	Detect	Insights: detecta datos protegidos incorrectamente S3 buckets	Insights: detects improperly secured data from S3 buckets
EC2 instances that are open to the Internet	AWSSecurityHub	Detect	Insights: detecta datos protegidos incorrectamente S3 buckets	Insights: detects improperly secured data from S3 buckets
EC2 instances that have ports accessible from the Internet	AWSSecurityHub	Detect	Insights: detecta datos protegidos incorrectamente S3 buckets	Insights: detects improperly secured data from S3 buckets
Backdoor:EC2/DenialOfService.Dns	AmazonGuardDuty	Detect	Los adversarios pueden realizar ataques de denegación de servicio (DoS) de red para degradar o bloquear la disponibilidad de recursos específicos para los usuarios. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofservicedns	Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofservicedns
Backdoor:EC2/DenialOfService.Tcp	AmazonGuardDuty	Detect	Los adversarios pueden realizar ataques de denegación de servicio (DoS) de red para degradar o bloquear la disponibilidad de recursos específicos para los usuarios. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofservicetcp	Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofservicetcp
Backdoor:EC2/DenialOfService.Udp	AmazonGuardDuty	Detect	Los adversarios pueden realizar ataques de denegación de servicio (DoS) de red para degradar o bloquear la disponibilidad de los recursos específicos para los usuarios. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceudp	Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceudp
Backdoor:EC2/DenialOfService.UdpOnTcpPorts	AmazonGuardDuty	Detect	Los adversarios pueden realizar ataques de denegación de servicio (DoS) de red para degradar o bloquear la disponibilidad de los recursos específicos para los usuarios. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceudpontcpports	Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceudpontcpports
Backdoor:EC2/DenialOfService.UnusualProtocol	AmazonGuardDuty	Detect	Los adversarios pueden realizar ataques de denegación de servicio (DoS) de red para degradar o bloquear la disponibilidad de los recursos específicos para los usuarios. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceunusualprotocol	Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceunusualprotocol
CryptoCurrency:EC2/BitcoinTool.B!DNS	AmazonGuardDuty	Detect	Los adversarios pueden aprovechar los recursos de los sistemas cooptados para resolver problemas intensivos en recursos que pueden afectar la disponibilidad del sistema y/o del servicio alojado. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolbdns	Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolbdns
Discovery:S3/MaliciousIPCaller	AmazonGuardDuty	Detect	Un usuario malintencionado puede estar buscando en la cuenta los recursos disponibles. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-maliciousipcaller	A malicious user may be searching through the account looking for available resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-maliciousipcaller
Discovery:S3/MaliciousIPCaller.Custom	AmazonGuardDuty	Detect	Un usuario malintencionado puede estar buscando en la cuenta los recursos disponibles. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-maliciousipcallercustom	A malicious user may be searching through the account looking for available resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-maliciousipcallercustom
Discovery:S3/TorIPCaller	AmazonGuardDuty	Detect	Un usuario malintencionado puede estar buscando en la cuenta los recursos disponibles. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-toripcaller	A malicious user may be searching through the account looking for available resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-toripcaller
Exfiltration:IAMUser/AnomalousBehavior	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#exfiltration-iam-anomalousbehavior	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#exfiltration-iam-anomalousbehavior
Impact:EC2/BitcoinDomainRequest.Reputation	AmazonGuardDuty	Detect	Los adversarios pueden aprovechar los recursos de los sistemas para resolver problemas intensivos en recursos que pueden afectar la disponibilidad del servicio alojado. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-bitcoindomainrequestreputation	Adversaries may leverage the resources of systems in order to solve resource intensive problems which may impact hosted service availability. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-bitcoindomainrequestreputation
Impact:EC2/PortSweep	AmazonGuardDuty	Detect	Detectado un intento de obtener una lista de servicios que se ejecutan en un host remoto. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-portsweep	There is an attempt to get a list of services running on a remote host. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-portsweep
Impact:EC2/WinRMBruteForce	AmazonGuardDuty	Detect	Una instancia EC2 puede verse involucrada en un ataque de fuerza bruta destinado a obtener contraseñas. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-winrmbruteforce	An EC2 instance may be involved in a brute force attack aimed at obtaining passwords. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-winrmbruteforce
Impact:S3/MaliciousIPCaller	AmazonGuardDuty	Detect	Los adversarios podrían cifrar o destruir datos y archivos en sistemas específicos para interrumpir la disponibilidad de sistemas, servicios y recursos de red. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-maliciousipcaller	Adversaries may encrypt or destroy data and files on specific systems to interrupt availability to systems, services, and network resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-maliciousipcaller
PenTest:IAMUser/KaliLinux	AmazonGuardDuty	Detect	Marca una instancia en la que hay indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-kalilinux	Flags an instance where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-kalilinux
PenTest:IAMUser/ParrotLinux	AmazonGuardDuty	Detect	Marca una instancia en la que hay indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-parrotlinux	Flags an instance where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-parrotlinux
PenTest:S3/KaliLinux	AmazonGuardDuty	Detect	Los adversarios podrían cifrar o destruir datos y archivos en sistemas específicos para interrumpir la disponibilidad de sistemas, servicios y recursos de red. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-kalilinux	Adversaries may encrypt or destroy data and files on specific systems to interrupt availability to systems, services, and network resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-kalilinux
PenTest:S3/ParrotLinux	AmazonGuardDuty	Detect	Los adversarios podrían cifrar o destruir datos y archivos en sistemas específicos para interrumpir la disponibilidad de sistemas, servicios y recursos de red. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-parrotlinux	Adversaries may encrypt or destroy data and files on specific systems to interrupt availability to systems, services, and network resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-parrotlinux
PenTest:S3/PentooLinux	AmazonGuardDuty	Detect	Los adversarios podrían cifrar o destruir datos y archivos en sistemas específicos para interrumpir la disponibilidad de sistemas, servicios y recursos de red. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-pentoolinux	Adversaries may encrypt or destroy data and files on specific systems to interrupt availability to systems, services, and network resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-pentoolinux
Recon:EC2/Portscan	AmazonGuardDuty	Detect	There is an attempt to get a list of services running on a remote host. Remediation/recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portscan	There is an attempt to get a list of services running on a remote host. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portscan
Recon:IAMUser/MaliciousIPCaller	AmazonGuardDuty	Detect	Marca una instancia en la que hay indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-maliciousipcaller	Flags an instance where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-maliciousipcaller
Recon:IAMUser/MaliciousIPCaller.Custom	AmazonGuardDuty	Detect	Marca una instancia en la que hay indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-maliciousipcallercustom	Flags an instance where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-maliciousipcallercustom
Stealth:IAMUser/CloudTrailLoggingDisabled	AmazonGuardDuty	Detect	Detectados indicios de actividad maliciosa en medidas de defensa. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-cloudtrailloggingdisabled	Provides indicators of malicious activity in defense measures. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-cloudtrailloggingdisabled
Stealth:S3/ServerAccessLoggingDisabled	AmazonGuardDuty	Detect	Los adversarios podrían cifrar o destruir datos y archivos en sistemas específicos para interrumpir la disponibilidad de sistemas, servicios y recursos de red. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#stealth-s3-serveraccessloggingdisabled	Adversaries may encrypt or destroy data and files on specific systems to interrupt availability to systems, services, and network resources. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#stealth-s3-serveraccessloggingdisabled
CredentialAccess:IAMUser/AnomalousBehavior	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Recomendaciones/remediación: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#credentialaccess-iam-anomalousbehavior	Flags a session token where there are indications of account compromise. Remediation/recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#credentialaccess-iam-anomalousbehavior
Discovery:IAMUser/AnomalousBehavior	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#discovery-iam-anomalousbehavior	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#discovery-iam-anomalousbehavior
Impact:IAMUser/AnomalousBehavior	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#impact-iam-anomalousbehavior	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#impact-iam-anomalousbehavior
Policy:S3/AccountBlockPublicAccessDisabled	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-accountblockpublicaccessdisabled	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-accountblockpublicaccessdisabled
Policy:S3/BucketAnonymousAccessGranted	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketanonymousaccessgranted	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketanonymousaccessgranted
Persistence:IAMUser/AnomalousBehavior	AmazonGuardDuty	Detect	Flags a session token where there are indications of account compromise. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#persistence-iam-anomalousbehavior	Marca un token de sesión con indicios de compromiso de la cuenta. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#persistence-iam-anomalousbehavior
Policy:IAMUser/RootCredentialUsage	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#policy-iam-rootcredentialusage	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#policy-iam-rootcredentialusage
Policy:S3/BucketBlockPublicAccessDisabled	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketblockpublicaccessdisabled	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketblockpublicaccessdisabled
UnauthorizedAccess:IAMUser/ConsoleLogin	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-consoleloginsuccessb	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-consoleloginsuccessb
UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B	AmazonGuardDuty	Detect	Marca un token de sesión con indicios de compromiso de la cuenta. Remediación/recomendaciones: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-consoleloginsuccessb	Flags a session token where there are indications of account compromise. Remediation recommendations: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-consoleloginsuccessb
\.


                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 4441.dat                                                                                            0000600 0004000 0002000 00000001565 14362250175 0014262 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        HR-03	Security training and awareness-raising programme
IDM-01	Policy for system and data access authorisations
IDM-02	User registration
IDM-06	Administrator authorisations
IDM-08	Secure login methods
IDM-11	Password requirements and validation parameters
IDM-12	Restriction and control of administrative software
KOS-01	Technical safeguards
KOS-02	Monitoring of connections
KOS-03	Cross-network access
KRY-02	Encryption of data for transmission (transport encryption)
KRY-03	Encryption of sensitive data for storage
RB-05	Protection against malware
RB-06	Data backup and restoration â€“ concept
RB-21	Handling of vulnerabilities, malfunctions and errors â€“ check of open vulnerabilities
RB-22	Handling of vulnerabilities, malfunctions and errors â€“ system hardening
RB-23	Segregation of stored and processed data of the cloud customers in jointly used resources
\.


                                                                                                                                           4442.dat                                                                                            0000600 0004000 0002000 00000016371 14362250175 0014264 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        1.1	Establish and Maintain Detailed Enterprise Asset Inventory
1.2	Address Unauthorized Assets
1.4	Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory
10.1	Deploy and Maintain Anti-Malware Software
10.2	Configure Automatic Anti-Malware Signature Updates
10.3	Disable Autorun and Autoplay for Removable Media
10.5	Enable Anti-Exploitation Features
10.7	Use Behavior-Based Anti-Malware Software
11.1	Establish and Maintain a Data Recovery ProcessÂ 
11.2	Perform Automated BackupsÂ 
11.3	Protect Recovery Data
11.4	Establish and Maintain an Isolated Instance of Recovery DataÂ 
11.5	Test Data Recovery
12.1	Ensure Network Infrastructure is Up-to-Date
12.2	Establish and Maintain a Secure Network Architecture
12.5	Centralize Network Authentication, Authorization, and Auditing (AAA)
12.6	Use of Secure Network Management and Communication ProtocolsÂ 
12.7	Ensure Remote Devices Utilize a VPN and are Connecting to an Enterpriseâ€™s AAA Infrastructure
12.8	Establish and Maintain Dedicated Computing Resources for All Administrative Work
13.1	Centralize Security Event Alerting
13.2	Deploy a Host-Based Intrusion Detection Solution
13.3	Deploy a Network Intrusion Detection Solution
13.4	Perform Traffic Filtering Between Network Segments
13.5	Manage Access Control for Remote Assets
13.7	Deploy a Host-Based Intrusion Prevention Solution
13.8	Deploy a Network Intrusion Prevention Solution
13.9	Deploy Port-Level Access Control
14.1	Establish and Maintain a Security Awareness Program
14.2	Train Workforce Members to Recognize Social Engineering Attacks
14.3	Train Workforce Members on Authentication Best Practices
14.4	Train Workforce on Data Handling Best Practices
14.5	Train Workforce Members on Causes of Unintentional Data Exposure
14.6	Train Workforce Members on Recognizing and Reporting Security Incidents
14.9	Conduct Role-Specific Security Awareness and Skills Training
15.7	Securely Decommission Service Providers
16.1	Establish and Maintain a Secure Application DevelopmentÂ Process
16.11	Leverage Vetted Modules or Services for Application Security Components
16.12	Implement Code-Level Security Checks
16.13	Conduct Application Penetration Testing
16.2	Establish and Maintain a Process to Accept and Address Software Vulnerabilities
16.3	Perform Root Cause Analysis on Security Vulnerabilities
16.4	Establish and Manage an Inventory of Third-Party Software Components
16.5	Use Up-to-Date and Trusted Third-Party Software Components
16.8	Separate Production and Non-Production Systems
16.9	Train Developers in Application Security Concepts and Secure Coding
18.1	Establish and Maintain a Penetration Testing Program
18.2	Perform Periodic External Penetration Tests
18.3	Remediate Penetration Test Findings
18.5	Perform Periodic Internal Penetration Tests
2.1	Establish and Maintain a Software Inventory
2.2	Ensure Authorized Software is Currently Supported 
2.3	Address Unauthorized Software
2.4	Utilize Automated Software Inventory Tools
2.5	Allowlist Authorized Software
2.6	Allowlist Authorized Libraries
2.7	Allowlist Authorized Scripts
3.1	Establish and Maintain a Data Management Process
3.11	Encrypt Sensitive Data at Rest
3.12	Segment Data Processing and Storage Based on Sensitivity
3.3	Configure Data Access Control Lists
3.4	Enforce Data Retention
3.6	Encrypt Data on End-User Devices
4.1	Establish and Maintain a Secure Configuration Process
4.2	Establish and Maintain a Secure Configuration Process for Network Infrastructure
4.4	Implement and Manage a Firewall on Servers
4.5	Implement and Manage a Firewall on End-User Devices
4.6	Securely Manage Enterprise Assets and Software
4.7	Manage Default Accounts on Enterprise Assets and Software
4.8	Uninstall or Disable Unnecessary Services on Enterprise Assets and Software
4.9	Configure Trusted DNS Servers on Enterprise Assets
5.1	Establish and Maintain an Inventory of Accounts
5.2	Use Unique Passwords
5.3	Disable Dormant Accounts
5.4	Restrict Administrator Privileges to Dedicated Administrator Accounts
5.5	Establish and Maintain an Inventory of Service Accounts
6.1	Establish an Access Granting Process
6.2	Establish an Access Revoking Process
6.3	Require MFA for Externally-Exposed Applications
6.4	Require MFA for Remote Network Access
6.5	Require MFA for Administrative Access
6.8	Define and Maintain Role-Based Access Control
7.1	Establish and Maintain a Vulnerability Management Process
7.2	Establish and Maintain a Remediation Process
7.3	Perform Automated Operating System Patch Management
7.4	Perform Automated Application Patch Management
7.5	Perform Automated Vulnerability Scans of Internal Enterprise Assets
7.6	Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets
7.7	Remediate Detected Vulnerabilities
8.1	Establish and maintain an audit log management process that defines the enterpriseâ€™s logging requirements. 
8.11	Conduct reviews of audit logs to detect anomalies or abnormal events that could indicate a potential threat. Conduct reviews on a weekly, or more frequent, basis.
8.2	Collect Audit Logs
8.3	Ensure Adequate Audit Log Storage
8.5	Collect Detailed Audit Logs
8.9	Centralize Audit Logs
9.1	Ensure Use of Only Fully Supported Browsers and Email Clients
9.2	Use DNS Filtering Services
9.3	Maintain and Enforce Network-Based URL Filters
9.4	Restrict Unnecessary or Unauthorized Browser and Email Client Extensions
9.6	Block Unnecessary File Types
9.7	Deploy and Maintain Email Server Anti-Malware Protections
3.2	Establish and Maintain a Data Inventory
1.3	Utilize an Active Discovery Tool
1.5	Use a Passive Asset Discovery Tool
10.4	Configure Automatic Anti-Malware \nScanning of Removable Media
10.6	Centrally Manage Anti-Malware Software
12.3	Securely Manage Network Infrastructure
12.4	Establish and Maintain Architecture \nDiagram(s)
13.10	Perform Application Layer Filtering
13.11	Tune Security Event Alerting Thresholds
13.6	Collect Network Traffic Flow Logs
14.7	Train Workforce
14.8	Train Workforce
15.2	Establish and Maintain a Service Provider \nManagement Policy
15.3	Classify Service Providers
15.4	Ensure Service Provider Contracts Include \nSecurity Requirements
15.5	Assess Service Providers
15.6	Monitor Service Providers
16.10	Apply Secure Design Principles in \nApplication Architectures
16.6	Establish and Maintain a Severity Rating \nSystem and Process for Application \nVulnerabilities
16.7	Use Standard Hardening Configuration \nTemplates for Application Infrastructure
17.8	Conduct Post-Incident Reviews
3.10	Encrypt Sensitive Data in Transit
3.13	Deploy a Data Loss Prevention Solution
3.14	Log Sensitive Data Access
3.5	Securely Dispose of Data
3.7	Establish and Maintain a Data \nClassification Scheme
3.8	Document Data Flows
3.9	Encrypt Data on Removable Media
4.10	Enforce Automatic Device Lockout on Portable End-User Devices
4.11	Enforce Remote Wipe Capability on \nPortable End-User Devices
4.12	Separate Enterprise Workspaces on Mobile \nEnd-User Devices
4.3	Configure Automatic Session Locking on \nEnterprise Assets
5.6	Centralize Account Management
6.6	Establish and Maintain an Inventory of \nAuthentication and Authorization Systems
6.7	Centralize Access Contro
8.10	Retain Audit Logs
8.12	Collect Service Provider Logs
8.4	Standardize Time Synchronization
8.6	Collect DNS Query Audit Logs
8.7	Collect URL Request Audit Logs
8.8	Collect Command-Line Audit Logs
9.5	Implement DMARC
\.


                                                                                                                                                                                                                                                                       4443.dat                                                                                            0000600 0004000 0002000 00000005140 14362250175 0014255 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        1.1	CM-8
1.1	PM-5
1.2	CM-8
1.3	SI-4
1.4	CM-8
1.5	CM-8
1.5	SI-4
2.1	CM-7
2.1	CM-8
2.1	MA-3
2.2	SA-22
2.3	CM-10
2.3	CM-11
2.3	CM-7
2.3	CM-8
2.4	CM-8
2.5	CM-10
2.5	CM-7
2.6	CM-7
2.7	CM-7
2.7	SI-7
7.1	RA-5
8.1	AU-1
8.1	AU-2
8.11	AU-6
8.11	AU-7
8.12	AU-2
8.2	AU-12
8.2	AU-2
8.2	AU-7
9.1	CM-10
9.1	SC-18
9.2	SI-8
9.3	SC-7
9.4	CM-10
9.4	CM-11
9.4	SC-18
9.5	SC-7
9.6	SI-3
9.6	SI-8
9.7	SI-16
9.7	SI-3
9.7	SI-8
10.1	SI-3
10.2	SI-3
10.3	MP-7
10.4	MP-7
10.4	SI-3
10.5	SI-16
10.6	SI-3
10.7	SI-4
11.1	CP-10
11.1	CP-2
11.2	CP-10
11.2	CP-9
11.3	CP-9
11.3	SC-28
11.4	CP-6
11.5	CP-4
11.5	CP-9
12.1	CM-8
12.2	CM-7
12.2	CP-6
12.2	CP-7
12.2	PL-8
12.2	PM-7
12.2	SA-8
12.2	SC-7
12.3	CM-6
12.3	CM-7
12.3	SC-23
12.4	PL-8
12.4	PM-5
12.5	AC-2
12.6	AC-18
12.6	SC-23
12.7	AC-17
12.8	AC-17
12.8	SI-7
13.1	AU-6
13.1	AU-7
13.1	IR-4
13.1	SI-4
13.11	SI-4
13.3	SI-4
13.4	CA-9
13.4	SC-7
13.5	AC-17
13.5	SC-7
13.5	SI-4
13.6	SI-4
13.8	SI-4
13.9	CM-6
13.9	CM-7
14.1	AT-1
14.1	AT-2
14.1	PM-13
14.2	AT-2
14.3	AT-2
14.4	AT-2
14.5	AC-22
14.6	AT-2
14.7	AT-2
14.8	AT-2
14.9	AT-3
15.1	PM-30
15.2	AC-20
15.2	AC-21
15.2	PM-30
15.2	SA-9
15.2	SR-1
15.2	SR-6
15.3	AC-20
15.3	PM-17
15.3	SR-5
15.4	SA-4
15.4	SR-5
15.4	SR-6
15.5	AC-20
15.5	SI-4
16.1	SA-3
16.11	SA-15
16.12	SA-11
16.12	SA-15
16.14	RA-3
16.2	CA-5
16.2	RA-1
16.2	RA-5
16.2	RA-7
16.3	SI-2
16.4	CM-8
16.5	SR-11
16.6	RA-5
16.7	CM-6
16.7	CM-7
16.8	SC-7
16.9	SA-8
17.1	IR-1
17.1	IR-7
17.1	IR-8
17.2	IR-6
17.6	CP-8
17.6	IR-8
17.7	IR-3
17.8	IR-4
17.9	IR-6
17.9	IR-8
13.10	SC-7
15.6	SR-6
15.7	SR-12
16.10	PL-8
16.10	SA-8
17.3	IR-5
17.3	IR-6
17.3	IR-8
17.4	IR-1
17.4	IR-6
17.4	IR-8
17.5	IR-1
17.5	IR-8
3.1	AU-11
3.1	CM-12
3.1	SI-12
3.10	AC-17
3.10	IA-5
3.10	SC-8
3.11	IA-5
3.11	SC-28
3.13	CA-7
3.13	CM-12
3.13	SC-4
3.14	AC-6
3.14	AU-12
3.14	AU-2
3.2	CM-12
3.2	PM-5
3.2	RA-2
3.3	AC-3
3.3	AC-5
3.3	AC-6
3.3	MP-2
3.4	AU-11
3.4	SI-12
3.5	MP-6
3.5	SR-12
3.6	SC-28
3.7	RA-2
3.8	AC-4
3.8	CM-12
3.9	MP-5
3.9	MP-7
4.1	CM-1
4.1	CM-2
4.1	CM-6
4.1	CM-7
4.1	CM-9
4.1	SA-10
4.1	SA-3
4.1	SA-8
4.10	AC-19
4.10	AC-7
4.11	AC-19
4.11	AC-20
4.12	AC-19
4.12	SC-39
4.2	AC-18
4.2	CM-2
4.2	CM-6
4.2	CM-7
4.2	CM-9
4.3	AC-11
4.3	AC-12
4.3	AC-2
4.4	CA-9
4.4	SC-7
4.5	SC-7
4.6	CM-7
4.6	MA-4
4.7	IA-5
4.8	CM-6
4.8	CM-7
4.9	SC-20
4.9	SC-21
4.9	SC-22
5.1	AC-2
5.2	IA-5
5.3	AC-2
5.4	AC-6
5.5	AC-2
5.6	AC-2
6.1	AC-1
6.1	AC-2
6.1	IA-4
6.1	IA-5
6.2	AC-1
6.2	AC-2
6.3	IA-2
6.4	AC-19
6.4	IA-2
6.5	IA-2
6.6	CM-8
6.6	IA-8(2)
6.7	AC-2
6.7	AC-3
6.8	AC-2
6.8	AC-5
6.8	AC-6
6.8	AU-9
7.2	RA-5
7.3	RA-5
7.3	RA-7
7.3	SI-2
7.4	RA-5
7.4	RA-7
7.4	SI-2
7.5	RA-5
7.6	RA-5
7.7	RA-5
7.7	RA-7
7.7	SI-2
8.10	AU-11
8.3	AU-4
8.4	AU-7
8.4	AU-8
8.5	AU-12
8.5	AU-3
8.5	AU-7
8.6	AU-2
8.7	AU-2
8.8	AU-2
8.9	AU-6
\.


                                                                                                                                                                                                                                                                                                                                                                                                                                4444.dat                                                                                            0000600 0004000 0002000 00000007227 14362250175 0014266 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        1	8.2
1	8.3
1	2.4
1	9.5
1	9.6
1	9.7
1	9.8
1	9.9
1	1.1.1
1	1.1.2
1	1.1.3
1	10.1
1	12.10.5
1	10.6
3	1.2
3	2.2
3	7.1
3	7.2
3	9.3
3	10.6
3	12.5.2
3	10.1
3	12.10.5
4	6.1
4	11.3
4	12.2
4	12.10.1
4	6.5
4	11.2
4	1.1.1
4	1.1.2
4	1.1.3
4	10.1
4	10.6
4	5
4	11.5.1
4	12.5.2
4	12.10.5
4	6.2
4	10.6.3
4	12.1
5	1.1.5
5	7.1
5	7.2
5	7.3
5	12.4
5	12.6
5	8.1.3
5	9.3
5	12.7
5	10.1
5	12.10.5
5	10.6
5	9.1.1
6	1.1.1
6	1.1.2
6	1.1.3
6	10.6
6	12.5.2
6	10.1
6	12.10.5
6	10.6.3
6	11.5.1
7	10.1
7	12.10.5
7	10.6
7	10.6.1
7	10.6.2
7	11.4
7	9.1.1
7	5
8	1
8	2
8	10.1
8	10.6
8	10.6.1
8	10.6.2
8	11.4
8	5
8	10.6.3
8	11.5.1
8	12.5.2
8	12.10.5
9	1.1
9	1.3
9	6.2
9	10.8
9	11.3
9	1.2
9	2.2
10	9.5.1
10	12.10.1
10	12.10.2
10	12.10.6
11	1.2
11	2.2
11	7.1
11	7.2
11	9.3
11	10.1
11	12.10.5
11	10.6
12	1.1.2
12	1.1.3
12	1.1.1
12	2.4
12	6.4.2
12	7.1
12	7.2
12	8.7
12	9.3
12	8.2
12	8.3
12	1
12	2
12	10.1
12	12.10.5
12	10.6
12	10.6.1
12	10.6.2
12	11.4
12	5
13	9.6.1
13	12.2
13	8.2.1
13	10.6
13	1.1.1
13	1.1.2
13	1.1.3
13	12.5.2
13	10.1
13	12.10.5
13	10.6.1
13	10.6.2
13	11.4
14	9.6.1
14	12.2
14	6.4.2
14	7.1
14	7.2
14	8.7
14	9.3
14	1.1
14	1.2
14	1.3
14	2.2
14	6.2
14	10.8
14	11.3
14	8.2.1
14	10.1
14	12.10.5
14	10.6
14	9.1.1
15	2.1
15	8.1
15	8.5
15	8.6
15	12.3
15	6.4.2
15	7.1
15	7.2
15	8.7
15	9.3
15	1.1
15	1.2
15	1.3
15	2.2
15	6.2
15	10.8
15	11.3
15	8.2
15	8.3
15	1
15	2
15	1.1.1
15	1.1.2
15	1.1.3
15	10.6
15	12.5.2
15	10.1
15	12.10.5
15	10.6.1
15	10.6.2
15	11.4
16	2.1
16	8.1
16	8.5
16	8.6
16	12.3
16	6.4.2
16	7.1
16	7.2
16	8.7
16	9.3
16	7.1.4
16	8.2.2
16	8.2
16	8.3
16	8.1.3
16	12.7
16	1.1.1
16	1.1.2
16	1.1.3
16	10.1
16	12.10.5
16	10.6
16	10.6.1
16	10.6.2
16	11.4
16	9.1.1
17	6.7
17	7.3
17	8.4
17	9.9.3
17	12.6
17	1.1.5
17	7.1
17	7.2
17	12.8.2
17	12.9
17	12.4
18	6.4.2
18	8.7
18	9.3
18	1.1
18	1.2
18	1.3
18	2.2
18	6.2
18	10.8
18	11.3
18	7.3
18	8.4
18	9.9.3
18	12.4
18	12.6
18	1.1.5
18	7.1
18	7.2
18	6.4.1
18	6.3
18	6.4
18	6.5
18	6.6
18	6.7
18	6.1
18	11.2
19	12.4
19	12.8
19	12.9
19	12.1
19	12.5
19	11.1.2
19	12.5.3
19	12.10.2
19	9.9.3
19	12.5.2
19	10.8
19	12.10.1
19	10.6.3
19	11.5.1
19	12.10.5
20	12.1
20	6.4.1
20	6.4.2
20	12.10.2
20	6.1
20	6.2
20	6.5
20	11.2
117	12.4
117	12.5
117	12.8
117	12.9
1.1	2.4
1.1	9.9.1
1.1	11.1.1
1.5	11.1
1.5	11.1.2
1.5	2.1
1.5	8.1
1.5	8.2
1.5	8.5
1.5	8.6
1.5	12.3
10.1	5.1
10.2	5.1.1
10.2	5.2
10.2	11.4
10.5	1.4
10.6	11.4
11.2	12.10.1
11.3	9.5
11.3	9.5.1
12.2	1.1.6
12.2	1.2.3
12.2	2.2.2
12.3	8.3
12.6	2.1.1
12.6	4.1.1
13.1	10.5.3
13.1	10.6.1
13.10	1.1.4
13.10	1.2
13.10	1.3.2
13.10	1.3.3
13.10	1.3.4
13.10	1.3.5
13.10	6.6
13.2	11.4
13.3	11.4
13.7	11.4
13.8	11.1
13.8	11.4
13.9	1.1.6
13.9	1.2
14.1	9.9.3
14.1	12.6
14.1	12.6.1
14.1	12.6.2
14.4	12.6
14.9	12.10.4
14.9	6.5
16.1	6.3
16.1	6.5
16.12	6.3.2
16.2	6.3.2
16.5	6.2
16.6	6.1
16.7	2.2
16.8	6.4.1
16.8	6.4.2
16.9	6.5
16.9	6.5.1
16.9	6.5.2
16.9	6.5.3
16.9	6.5.4
16.9	6.5.5
16.9	6.5.6
16.9	6.5.7
16.9	6.5.8
16.9	6.5.9
16.9	6.5.10
17.1	12.10.3
17.1	12.10.4
17.3	12.10.1
17.4	12.10.1
18.1	11.3
18.2	11.3.1
18.5	11.3.2
2.1	2.4
2.1	1.1.6
2.3	11.5
3.10	2.1.1
3.10	4.1
3.10	4.1.1
3.10	8.2.1
3.11	3.4
3.11	3.4.1 
3.11	8.2.1
3.12	2.2.1
3.12	2.4
3.12	7.1
3.14	10.2.1
3.14	11.5
3.2	9.6.1
3.3	7.1
3.3	7.1.1
3.3	7.1.2
3.3	7.1.3
3.7	9.6.1
3.8	1.1.2
3.8	1.1.3
3.9	3.4
4.1	2.2
4.1	11.5
4.2	1.1.1
4.2	1.2.2
4.3	8.1.8
4.4	1.1.4
4.4	1.3.1
4.5	1.4
4.5	1.1.4
4.7	2.1
4.7	2.1.1
4.8	1.1.6
4.8	1.2.1
4.8	2.2.2
4.8	2.2.5
4.8	12.2
4.8	12.8
4.8	12.9
5.1	8.1
5.1	8.1.1
5.3	8.1.4
5.4	7.1
5.4	7.1.1
5.4	7.1.2
5.4	7.1.3
6.2	8.1.3
6.3	8.3
6.4	2.3
6.4	8.3
6.4	8.3.2
6.5	8.3
6.5	8.3.1
6.5	8.3.2
7.2	11.2.1
7.2	6.1
7.3	6.2
7.4	6.2
7.5	11.2
7.6	11.2
8.10	10.7
8.11	10.6
8.11	10.6.1
8.11	10.6.2
8.2	10.2
8.2	10.3
8.3	10.7
8.4	10.4
8.5	10.1
8.5	10.2.2
8.5	10.2.4
8.5	10.2.5
8.5	10.3
8.9	10.5.3
8.9	10.5.4
9.3	1.1.6
9.3	11.4
\.


                                                                                                                                                                                                                                                                                                                                                                         4445.dat                                                                                            0000600 0004000 0002000 00000001110 14362250175 0014250 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        mp.com.2	Confidentiality protection
mp.com.3	Integrity and authenticity protection
mp.com.4	Separation of information flows in the network
mp.info.6	Backups
mp.per.3	Training
mp.s.2	Services and Web Applications protection
mp.s.3	Web browsing protection
mp.s.4	DoS protection
mp.sw.1	Applications development
op.acc.2	Access requirements
op.acc.3	Tasks and duties segregation
op.acc.4	Access rights management process
op.acc.6	Authentication mechanism (users of the\norganization)
op.exp.2	Security settings
op.exp.8	Activity log
op.mon.1	Intrusion detection
op.mon.3	Monitoring
\.


                                                                                                                                                                                                                                                                                                                                                                                                                                                        4446.dat                                                                                            0000600 0004000 0002000 00000113357 14362250175 0014272 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        T1040	AmazonVirtualPrivatecloud	elb-tls-https-listeners-only
T1040	AWSCloudWatch	elb-tls-https-listeners-only
T1040	AWSConfig	acm-certificate-expiration-check
T1040	AWSConfig	alb-http-to-https-redirection-check
T1040	AWSConfig	api-gw-ssl-enabled
T1530	AWSConfig	s3-account-level-public-access-blocks-periodic
T1552.001	AWSConfig	s3-account-level-public-access-blocks-periodic
T1040	AWSConfig	elasticsearch-in-vpc-only
T1040	AWSConfig	elasticsearch-node-to-node-encryption-check
T1040	AWSConfig	elb-acm-certificate-required
T1040	AWSConfig	elb-predefined-security-policy-ssl-check
T1040	AWSConfig	elb-tls-https-listeners-only
T1040	AWSConfig	redshift-enhanced-vpc-routing-enabled
T1040	AWSConfig	redshift-require-tls-ssl
T1040	AWSConfig	s3-bucket-ssl-requests-only
T1040	AWSIOTDeviceDefender	CA_CERTIFICATE_EXPIRING_CHECK
T1040	AWSIOTDeviceDefender	CA_CERTIFICATE_KEY_QUALITY_CHECK
T1040	AWSIOTDeviceDefender	DEVICE_CERTIFICATE_EXPIRING_CHECK
T1040	AWSIOTDeviceDefender	DEVICE_CERTIFICATE_KEY_QUALITY_CHECK
T1040	AWSIOTDeviceDefender	DEVICE_CERTIFICATE_SHARED_CHECK
T1040	AWSIOTDeviceDefender	REVOKED_CA_CERTIFICATE_STILL_ACTIVE_CHECK
T1040	AWSIOTDeviceDefender	REVOKED_DEVICE_CERTIFICATE_STILL_ACTIVE_CHECK
T1040	AWSRDS	elb-tls-https-listeners-only
T1046	AmazonGuardDuty	Impact:EC2/PortSweep
T1046	AmazonGuardDuty	Recon:EC2/PortProbeEMRUnprotectedPort
T1528	AWSIAM	Impact:IAMUser/AnomalousBehavior
T1046	AmazonGuardDuty	Recon:EC2/PortProbeUnprotectedPort
T1046	AmazonGuardDuty	Recon:EC2/Portscan
T1046	AmazonInspector	Recon:EC2/Portscan
T1046	AmazonVirtualPrivatecloud	Recon:EC2/Portscan
T1046	AWSIOTDeviceDefender	aws:all-bytes-in
T1046	AWSIOTDeviceDefender	aws:all-bytes-out
T1046	AWSIOTDeviceDefender	aws:all-packets-in
T1046	AWSIOTDeviceDefender	aws:all-packets-out
T1046	AWSIOTDeviceDefender	aws:destination-ip-addresses
T1046	AWSIOTDeviceDefender	aws:listening-tcp-ports
T1046	AWSIOTDeviceDefender	aws:listening-udp-ports
T1046	AWSIOTDeviceDefender	aws:num-established-tcp-connections
T1046	AWSIOTDeviceDefender	aws:num-listening-tcp-ports
T1046	AWSIOTDeviceDefender	aws:num-listening-udp-ports
T1046	AWSNetworkFirewall	Recon:EC2/Portscan
T1046	AWSWebApplicationFirewall	Recon:EC2/Portscan
T1046	AWSWebApplicationFirewall	Recon:EC2/PortProbeUnprotectedPort
T1078.001	AmazonGuardDuty	CredentialAccess:IAMUser/AnomalousBehavior
T1078.001	AmazonGuardDuty	DefenseEvasion:IAMUser/AnomalousBehavior
T1078.001	AmazonGuardDuty	Discovery:IAMUser/AnomalousBehavior
T1078.001	AmazonGuardDuty	Exfiltration:IAMUser/AnomalousBehavior
T1078.001	AmazonGuardDuty	Impact:IAMUser/AnomalousBehavior
T1078.001	AmazonGuardDuty	PenTest:IAMUser/KaliLinux
T1078.001	AmazonGuardDuty	PenTest:IAMUser/ParrotLinux
T1078.001	AmazonGuardDuty	PenTest:IAMUser/PentooLinux
T1078.001	AmazonGuardDuty	Persistence:IAMUser/AnomalousBehavior
T1078.001	AmazonGuardDuty	Policy:IAMUser/RootCredentialUsage
T1078.001	AmazonGuardDuty	Policy:S3/AccountBlockPublicAccessDisabled
T1078.001	AmazonGuardDuty	Policy:S3/BucketAnonymousAccessGranted
T1078.001	AmazonGuardDuty	Policy:S3/BucketBlockPublicAccessDisabled
T1078.001	AmazonGuardDuty	Policy:S3/BucketPublicAccessGranted
T1078.001	AmazonGuardDuty	Recon:IAMUser/MaliciousIPCaller
T1078.001	AmazonGuardDuty	Recon:IAMUser/MaliciousIPCaller.Custom
T1078.001	AmazonGuardDuty	UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
T1078.001	AmazonGuardDuty	UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
T1078.001	AmazonGuardDuty	UnauthorizedAccess:IAMUser/MaliciousIPCaller
T1078.001	AmazonGuardDuty	UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom
T1078.001	AmazonGuardDuty	UnauthorizedAccess:IAMUser/TorIPCaller
T1078.004	AmazonCognito	CredentialAccess:IAMUser/AnomalousBehavior
T1078.004	AmazonGuardDuty	CredentialAccess:IAMUser/AnomalousBehavior
T1078.004	AmazonGuardDuty	DefenseEvasion:IAMUser/AnomalousBehavior
T1078.004	AmazonGuardDuty	Discovery:IAMUser/AnomalousBehavior
T1078.004	AmazonGuardDuty	Exfiltration:IAMUser/AnomalousBehavior
T1078.004	AmazonGuardDuty	Impact:IAMUser/AnomalousBehavior
T1078.004	AmazonGuardDuty	PenTest:IAMUser/KaliLinux
T1078.004	AmazonGuardDuty	PenTest:IAMUser/ParrotLinux
T1078.004	AmazonGuardDuty	PenTest:IAMUser/PentooLinux
T1078.004	AmazonGuardDuty	Persistence:IAMUser/AnomalousBehavior
T1078.004	AmazonGuardDuty	Policy:IAMUser/RootCredentialUsage
T1078.004	AmazonGuardDuty	Policy:S3/AccountBlockPublicAccessDisabled
T1078.004	AmazonGuardDuty	Policy:S3/BucketAnonymousAccessGranted
T1078.004	AmazonGuardDuty	Policy:S3/BucketBlockPublicAccessDisabled
T1078.004	AmazonGuardDuty	Policy:S3/BucketPublicAccessGranted
T1078.004	AmazonGuardDuty	Recon:IAMUser/MaliciousIPCaller
T1078.004	AmazonGuardDuty	Recon:IAMUser/MaliciousIPCaller.Custom
T1078.004	AmazonGuardDuty	UnauthorizedAccess:IAMUser/ConsoleLogin
T1078.004	AmazonGuardDuty	UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
T1078.004	AmazonGuardDuty	UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
T1078.004	AmazonGuardDuty	UnauthorizedAccess:IAMUser/MaliciousIPCaller
T1078.004	AmazonGuardDuty	UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom
T1078.004	AmazonGuardDuty	UnauthorizedAccess:IAMUser/TorIPCaller
T1078.004	AWSConfig	access-keys-rotated
T1078.004	AWSConfig	ec2-instance-profile-attached
T1078.004	AWSConfig	iam-password-policy
T1078.004	AWSConfig	iam-policy-no-statements-with-admin-access
T1078.004	AWSConfig	iam-policy-no-statements-with-full-access
T1078.004	AWSConfig	iam-root-access-key-check
T1078.004	AWSConfig	iam-user-group-membership-check
T1078.004	AWSConfig	iam-user-mfa-enabled
T1078.004	AWSConfig	iam-user-unused-credentials-check
T1078.004	AWSConfig	mfa-enabled-for-iam-console-access
T1078.004	AWSConfig	root-account-hardware-mfa-enabled
T1078.004	AWSConfig	root-account-mfa-enabled
T1078.004	AWSIAM	Discovery:IAMUser/AnomalousBehavior
T1078.004	AWSIOTDeviceDefender	AUTHENTICATED_COGNITO_ROLE_OVERLY_PERMISSIVE_CHECK
T1078.004	AWSIOTDeviceDefender	aws:num-authorization-failures
T1078.004	AWSIOTDeviceDefender	aws:num-connection-attempts
T1078.004	AWSIOTDeviceDefender	aws:num-disconnects
T1078.004	AWSIOTDeviceDefender	aws:source-ip-address
T1078.004	AWSIOTDeviceDefender	CONFLICTING_CLIENT_IDS_CHECK
T1078.004	AWSIOTDeviceDefender	DEVICE_CERTIFICATE_SHARED_CHECK
T1078.004	AWSIOTDeviceDefender	IOT_POLICY_OVERLY_PERMISSIVE_CHECK
T1078.004	AWSIOTDeviceDefender	IOT_ROLE_ALIAS_ALLOWS_ACCESS_TO_UNUSED_SERVICES_CHECK
T1078.004	AWSIOTDeviceDefender	IOT_ROLE_ALIAS_OVERLY_PERMISSIVE_CHECK
T1078.004	AWSIOTDeviceDefender	REVOKED_CA_CERTIFICATE_STILL_ACTIVE_CHECK
T1078.004	AWSIOTDeviceDefender	REVOKED_DEVICE_CERTIFICATE_STILL_ACTIVE_CHECK
T1078.004	AWSIOTDeviceDefender	UNAUTHENTICATED_COGNITO_ROLE_OVERLY_PERMISSIVE_CHECK
T1078.004	AWSOrganizations	Exfiltration:IAMUser/AnomalousBehavior
T1078.004	AWSSecurityHub	[PCI.CW.1] A log metric filter and alarm should exist for usage of the "root" user
T1078.004	AWSSecurityHub	3.1 Ensure a log metric filter and alarm exist for unauthorized API calls
T1078.004	AWSSecurityHub	3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA
T1078.004	AWSSecurityHub	3.3 Ensure a log metric filter and alarm exist for usage of "root" account 
T1078.004	AWSSecurityHub	3.4 Ensure a log metric filter and alarm exist for IAM policy changes
T1528	AWSSecretsManager	Impact:IAMUser/AnomalousBehavior
T1078.004	AWSSecurityHub	3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
T1078.004	AWSSecurityHub	AWS principals with suspicious access key activity
T1078.004	AWSSecurityHub	AWS resources with unauthorized access attempts
T1078.004	AWSSecurityHub	Credentials that may have leaked
T1078.004	AWSSecurityHub	IAM users with suspicious activity
T1078.004	AWSSSO	Exfiltration:IAMUser/AnomalousBehavior
T1087.004	AWSOrganizations	Discovery:IAMUser/AnomalousBehavior
T1098.001	AmazonGuardDuty	Persistence:IAMUser/AnomalousBehavior
T1098.001	AWSConfig	iam-user-mfa-enabled
T1098.001	AWSConfig	mfa-enabled-for-iam-console-access
T1098.001	AWSConfig	root-account-hardware-mfa-enabled
T1098.001	AWSConfig	root-account-mfa-enabled
T1098.001	AWSIAM	Persistence:IAMUser/AnomalousBehavior
T1098.001	AWSSecurityHub	3.4 Ensure a log metric filter and alarm exist for IAM policy changes 
T1098.004	AmazonGuardDuty	Persistence:IAMUser/AnomalousBehavior
T1110.001	AmazonCognito	iam-password-policy
T1110.001	AmazonGuardDuty	Impact:EC2/WinRMBruteForce
T1110.001	AmazonGuardDuty	Stealth:IAMUser/PasswordPolicyChange
T1110.001	AmazonGuardDuty	UnauthorizedAccess:EC2/RDPBruteForce
T1110.001	AmazonGuardDuty	UnauthorizedAccess:EC2/SSHBruteForce
T1110.001	AmazonInspector	UnauthorizedAccess:EC2/SSHBruteForce
T1110.001	AWSConfig	iam-password-policy
T1110.001	AWSConfig	iam-user-mfa-enabled
T1110.001	AWSConfig	mfa-enabled-for-iam-console-access
T1110.001	AWSConfig	root-account-hardware-mfa-enabled
T1110.001	AWSConfig	root-account-mfa-enabled
T1110.001	AWSIAM	Persistence:IAMUser/AnomalousBehavior
T1110.001	AWSSecurityHub	3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
T1110.001	AWSSSO	Impact:EC2/WinRMBruteForce
T1110.002	AmazonCognito	iam-user-mfa-enabled
T1110.002	AmazonInspector	iam-password-policy
T1110.002	AWSConfig	iam-password-policy
T1110.002	AWSConfig	iam-user-mfa-enabled
T1110.002	AWSConfig	mfa-enabled-for-iam-console-access
T1110.002	AWSConfig	root-account-hardware-mfa-enabled
T1110.002	AWSConfig	root-account-mfa-enabled
T1110.003	AmazonCognito	Impact:EC2/WinRMBruteForce
T1110.003	AmazonGuardDuty	Impact:EC2/WinRMBruteForce
T1110.003	AmazonGuardDuty	Stealth:IAMUser/PasswordPolicyChange
T1110.003	AmazonGuardDuty	UnauthorizedAccess:EC2/RDPBruteForce
T1110.003	AmazonGuardDuty	UnauthorizedAccess:EC2/SSHBruteForce
T1110.003	AmazonInspector	UnauthorizedAccess:EC2/SSHBruteForce
T1110.003	AWSConfig	iam-password-policy
T1110.003	AWSConfig	iam-user-mfa-enabled
T1110.003	AWSConfig	mfa-enabled-for-iam-console-access
T1110.003	AWSConfig	root-account-hardware-mfa-enabled
T1110.003	AWSConfig	root-account-mfa-enabled
T1110.003	AWSIAM	iam-user-mfa-enabled
T1110.003	AWSSecurityHub	3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
T1110.003	AWSSSO	iam-user-mfa-enabled
T1110.004	AmazonCognito	Impact:EC2/WinRMBruteForce
T1110.004	AmazonGuardDuty	Impact:EC2/WinRMBruteForce
T1110.004	AmazonGuardDuty	Stealth:IAMUser/PasswordPolicyChange
T1110.004	AmazonGuardDuty	UnauthorizedAccess:EC2/RDPBruteForce
T1110.004	AmazonGuardDuty	UnauthorizedAccess:EC2/SSHBruteForce
T1110.004	AmazonInspector	UnauthorizedAccess:EC2/SSHBruteForce
T1110.004	AWSConfig	iam-password-policy
T1110.004	AWSConfig	iam-user-mfa-enabled
T1110.004	AWSConfig	mfa-enabled-for-iam-console-access
T1110.004	AWSConfig	root-account-hardware-mfa-enabled
T1110.004	AWSConfig	root-account-mfa-enabled
T1110.004	AWSIAM	iam-user-mfa-enabled
T1110.004	AWSSecurityHub	3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
T1110.004	AWSSSO	iam-user-mfa-enabled
T1119	AWSConfig	ec2-ebs-encryption-by-default
T1119	AWSConfig	encrypted-volumes
T1136.003	AWSConfig	iam-user-mfa-enabled
T1136.003	AWSConfig	mfa-enabled-for-iam-console-access
T1136.003	AWSConfig	root-account-hardware-mfa-enabled
T1136.003	AWSConfig	root-account-mfa-enabled
T1189	AmazonGuardDuty	Trojan:EC2/DriveBySourceTraffic!DNS
T1189	AmazonInspector	Trojan:EC2/DriveBySourceTraffic!DNS
T1189	AWSWebApplicationFirewall	Trojan:EC2/DriveBySourceTraffic!DNS
T1190	AmazonGuardDuty	UnauthorizedAccess:EC2/MetadataDNSRebind
T1190	AmazonInspector	UnauthorizedAccess:EC2/MetadataDNSRebind
T1190	AWSConfig	ec2-instance-no-public-ip
T1190	AWSConfig	elastic-beanstalk-managed-updates-enabled
T1190	AWSConfig	elasticsearch-in-vpc-only
T1190	AWSConfig	lambda-function-public-access-prohibited
T1190	AWSConfig	rds-automatic-minor-version-upgrade-enabled
T1190	AWSRDS	rds-automatic-minor-version-upgrade-enabled
T1190	AWSSecurityHub	EC2 instances that have missing security patches for important vulnerabilities
T1190	AWSWebApplicationFirewall	UnauthorizedAccess:EC2/MetadataDNSRebind
T1201	AmazonGuardDuty	Discovery:IAMUser/AnomalousBehavior
T1485	AmazonGuardDuty	Impact:IAMUser/AnomalousBehavior
T1485	AmazonGuardDuty	Impact:S3/MaliciousIPCaller
T1485	AmazonGuardDuty	PenTest:S3/KaliLinux
T1485	AmazonGuardDuty	PenTest:S3/ParrotLinux
T1485	AmazonGuardDuty	PenTest:S3/PentooLinux
T1485	AmazonGuardDuty	Stealth:S3/ServerAccessLoggingDisabled
T1485	AmazonGuardDuty	UnauthorizedAccess:S3/MaliciousIPCaller.Custom
T1485	AmazonGuardDuty	UnauthorizedAccess:S3/TorIPCaller
T1485	AWSConfig	db-instance-backup-enabled
T1485	AWSConfig	dynamodb-in-backup-plan
T1485	AWSConfig	dynamodb-pitr-enabled
T1485	AWSConfig	ebs-in-backup-plan
T1485	AWSConfig	efs-in-backup-plan
T1485	AWSConfig	elasticache-redis-cluster-automatic-backup-check
T1485	AWSConfig	elb-deletion-protection-enabled
T1485	AWSConfig	rds-in-backup-plan
T1485	AWSConfig	rds-instance-deletion-protection-enabled
T1485	AWSConfig	redshift-backup-enabled
T1485	AWSConfig	redshift-cluster-maintenancesettings-check
T1485	AWSConfig	s3-bucket-default-lock-enabled
T1485	AWSConfig	s3-bucket-public-write-prohibited
T1485	AWSConfig	s3-bucket-replication-enabled
T1485	AWSConfig	s3-bucket-versioning-enabled
T1485	AWSRDS	rds-instance-deletion-protection-enabled
T1485	AWSS3	s3-bucket-versioning-enabled
T1485	AWSSecurityHub	Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
T1486	AmazonGuardDuty	Impact:S3/MaliciousIPCaller
T1486	AmazonGuardDuty	PenTest:S3/KaliLinux
T1486	AmazonGuardDuty	PenTest:S3/ParrotLinux
T1486	AmazonGuardDuty	PenTest:S3/PentooLinux
T1486	AmazonGuardDuty	Stealth:S3/ServerAccessLoggingDisabled
T1486	AmazonGuardDuty	UnauthorizedAccess:S3/MaliciousIPCaller.Custom
T1486	AmazonGuardDuty	UnauthorizedAccess:S3/TorIPCaller
T1486	AWSConfig	db-instance-backup-enabled
T1486	AWSConfig	dynamodb-in-backup-plan
T1486	AWSConfig	dynamodb-pitr-enabled
T1486	AWSConfig	ebs-in-backup-plan
T1486	AWSConfig	efs-in-backup-plan
T1486	AWSConfig	elasticache-redis-cluster-automatic-backup-check
T1486	AWSConfig	rds-in-backup-plan
T1486	AWSConfig	redshift-backup-enabled
T1486	AWSConfig	redshift-cluster-maintenancesettings-check
T1486	AWSConfig	s3-bucket-default-lock-enabled
T1486	AWSConfig	s3-bucket-public-write-prohibited
T1486	AWSConfig	s3-bucket-replication-enabled
T1486	AWSConfig	s3-bucket-versioning-enabled
T1491.002	AmazonGuardDuty	Exfiltration:S3/MaliciousIPCaller
T1491.002	AmazonGuardDuty	Impact:S3/MaliciousIPCaller
T1491.002	AmazonGuardDuty	PenTest:S3/KaliLinux
T1491.002	AmazonGuardDuty	PenTest:S3/ParrotLinux
T1491.002	AmazonGuardDuty	PenTest:S3/PentooLinux
T1491.002	AmazonGuardDuty	UnauthorizedAccess:S3/MaliciousIPCaller.Custom
T1491.002	AmazonGuardDuty	UnauthorizedAccess:S3/TorIPCaller
T1491.002	AWSConfig	db-instance-backup-enabled
T1491.002	AWSConfig	dynamodb-in-backup-plan
T1491.002	AWSConfig	dynamodb-pitr-enabled
T1491.002	AWSConfig	ebs-in-backup-plan
T1491.002	AWSConfig	efs-in-backup-plan
T1491.002	AWSConfig	elasticache-redis-cluster-automatic-backup-check
T1491.002	AWSConfig	rds-in-backup-plan
T1491.002	AWSConfig	redshift-backup-enabled
T1491.002	AWSConfig	redshift-cluster-maintenancesettings-check
T1491.002	AWSConfig	s3-bucket-default-lock-enabled
T1491.002	AWSConfig	s3-bucket-public-write-prohibited
T1491.002	AWSConfig	s3-bucket-replication-enabled
T1491.002	AWSConfig	s3-bucket-versioning-enabled
T1496	AmazonGuardDuty	CryptoCurrency:EC2/BitcoinTool.B
T1530	AWSConfig	rds-instance-public-access-check
T1496	AmazonGuardDuty	CryptoCurrency:EC2/BitcoinTool.B!DNS
T1496	AmazonGuardDuty	Impact:EC2/BitcoinDomainRequest.Reputation
T1496	AmazonGuardDuty	UnauthorizedAccess:EC2/TorRelay
T1496	AWSCloudWatch	CryptoCurrency:EC2/BitcoinTool.B
T1496	AWSConfig	cloudwatch-alarm-action-check
T1496	AWSConfig	dynamodb-throughput-limit-check
T1496	AWSConfig	rds-enhanced-monitoring-enabled
T1496	AWSIOTDeviceDefender	aws:all-bytes-in
T1496	AWSIOTDeviceDefender	aws:all-bytes-out
T1496	AWSIOTDeviceDefender	aws:all-packets-in
T1496	AWSIOTDeviceDefender	aws:all-packets-out
T1496	AWSIOTDeviceDefender	aws:destination-ip-addresses
T1496	AWSIOTDeviceDefender	aws:listening-tcp-ports
T1496	AWSIOTDeviceDefender	aws:listening-udp-ports
T1496	AWSIOTDeviceDefender	aws:num-established-tcp-connections
T1496	AWSIOTDeviceDefender	aws:num-listening-tcp-ports
T1496	AWSIOTDeviceDefender	aws:num-listening-udp-ports
T1498.001	AmazonGuardDuty	Backdoor:EC2/DenialOfService.Dns
T1498.001	AmazonGuardDuty	Backdoor:EC2/DenialOfService.Tcp
T1498.001	AmazonGuardDuty	Backdoor:EC2/DenialOfService.Udp
T1498.001	AmazonGuardDuty	Backdoor:EC2/DenialOfService.UdpOnTcpPorts
T1498.001	AmazonGuardDuty	Backdoor:EC2/DenialOfService.UnusualProtocol
T1498.001	AWSConfig	elb-cross-zone-load-balancing-enabled
T1498.001	AWSNetworkFirewall	Backdoor:EC2/DenialOfService.Dns
T1498.002	AmazonGuardDuty	Backdoor:EC2/DenialOfService.Dns
T1498.002	AmazonGuardDuty	Backdoor:EC2/DenialOfService.Tcp
T1530	AWSConfig	rds-storage-encrypted
T1498.002	AmazonGuardDuty	Backdoor:EC2/DenialOfService.Udp
T1498.002	AmazonGuardDuty	Backdoor:EC2/DenialOfService.UdpOnTcpPorts
T1498.002	AmazonGuardDuty	Backdoor:EC2/DenialOfService.UnusualProtocol
T1498.002	AWSConfig	elb-cross-zone-load-balancing-enabled
T1498.002	AWSNetworkFirewall	Backdoor:EC2/DenialOfService.Dns
T1499.002	AmazonVirtualPrivatecloud	Backdoor:EC2/DenialOfService.Dns
T1499.002	AWSConfig	elb-cross-zone-load-balancing-enabled
T1499.003	AWSConfig	elb-cross-zone-load-balancing-enabled
T1499.003	AWSNetworkFirewall	elb-cross-zone-load-balancing-enabled
T1499.004	AWSConfig	elb-cross-zone-load-balancing-enabled
T1526	AmazonGuardDuty	Recon:IAMUser/MaliciousIPCaller
T1526	AmazonGuardDuty	Recon:IAMUser/MaliciousIPCaller.Custom
T1526	AmazonGuardDuty	Recon:IAMUser/TorIPCaller
T1528	AmazonGuardDuty	Impact:IAMUser/AnomalousBehavior
T1530	AmazonGuardDuty	Exfiltration:S3/MaliciousIPCaller
T1530	AmazonGuardDuty	Impact:S3/MaliciousIPCaller
T1530	AmazonGuardDuty	PenTest:S3/KaliLinux
T1530	AmazonGuardDuty	PenTest:S3/ParrotLinux
T1530	AmazonGuardDuty	PenTest:S3/PentooLinux
T1530	AmazonGuardDuty	UnauthorizedAccess:S3/MaliciousIPCaller.Custom
T1530	AmazonGuardDuty	UnauthorizedAccess:S3/TorIPCaller
T1530	AmazonMacie	Policy:IAMUser/S3BlockPublicAccessDisabled
T1530	AmazonMacie	Policy:IAMUser/S3BucketEncryptionDisabled
T1530	AmazonMacie	Policy:IAMUser/S3BucketPublic
T1530	AmazonMacie	Policy:IAMUser/S3BucketReplicatedExternally
T1530	AmazonMacie	Policy:IAMUser/S3BucketSharedExternally
T1530	AmazonMacie	SensitiveData:S3Object/Credentials
T1530	AmazonMacie	SensitiveData:S3Object/CustomIdentifier
T1530	AmazonMacie	SensitiveData:S3Object/Financial
T1530	AmazonMacie	SensitiveData:S3Object/Multiple
T1530	AmazonMacie	SensitiveData:S3Object/Personal
T1530	AWSConfig	dms-replication-not-public 
T1530	AWSConfig	efs-encrypted-check
T1530	AWSConfig	elasticsearch-encrypted-at-rest
T1530	AWSConfig	emr-master-no-public-ip
T1530	AWSConfig	rds-snapshot-encrypted
T1530	AWSConfig	rds-snapshots-public-prohibited
T1530	AWSConfig	redshift-cluster-configuration-check
T1530	AWSConfig	redshift-cluster-kms-enabled
T1530	AWSConfig	redshift-cluster-public-access-check
T1530	AWSConfig	s3-bucket-level-public-access-prohibited
T1530	AWSConfig	s3-bucket-public-read-prohibited
T1530	AWSConfig	s3-bucket-server-side-encryption-enabled
T1530	AWSConfig	sagemaker-endpoint-configuration-kms-key-configured
T1530	AWSConfig	sagemaker-notebook-instance-kms-key-configured
T1530	AWSConfig	sagemaker-notebook-no-direct-internet-access
T1530	AWSConfig	sns-encrypted-kms
T1530	AWSIOTDeviceDefender	aws:all-bytes-in
T1530	AWSIOTDeviceDefender	aws:all-bytes-out
T1530	AWSIOTDeviceDefender	aws:all-packets-in
T1530	AWSIOTDeviceDefender	aws:all-packets-out
T1530	AWSIOTDeviceDefender	aws:message-byte-size
T1530	AWSIOTDeviceDefender	aws:num-messages-received
T1530	AWSIOTDeviceDefender	aws:num-messages-sent
T1530	AWSIOTDeviceDefender	aws:source-ip-address
T1530	AWSNetworkFirewall	Exfiltration:S3/MaliciousIPCaller
T1530	AWSRDS	rds-storage-encrypted
T1530	AWSSecurityHub	3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes 
T1530	AWSSecurityHub	S3 buckets with public write or read permissions
T1531	AmazonGuardDuty	Impact:IAMUser/AnomalousBehavior
T1531	AWSSecurityHub	3.4 Ensure a log metric filter and alarm exist for IAM policy changes 
T1535	AWSIAM	multi-region-cloudtrail-enabled
T1552.001	AWSKeyManagementService	encrypted-volumes
T1535	AWSConfig	multi-region-cloudtrail-enabled
T1537	AmazonMacie	Policy:IAMUser/S3BucketReplicatedExternally
T1537	AmazonMacie	Policy:IAMUser/S3BucketSharedExternally
T1538	AWSConfig	mfa-enabled-for-iam-console-access
T1538	AWSOrganizations	mfa-enabled-for-iam-console-access
T1552.001	AmazonGuardDuty	Exfiltration:S3/MaliciousIPCaller
T1552.001	AmazonGuardDuty	Impact:S3/MaliciousIPCaller
T1552.001	AmazonGuardDuty	PenTest:S3/KaliLinux
T1552.001	AmazonGuardDuty	PenTest:S3/ParrotLinux
T1552.001	AmazonGuardDuty	PenTest:S3/PentooLinux
T1552.001	AmazonGuardDuty	UnauthorizedAccess:S3/MaliciousIPCaller.Custom
T1552.001	AmazonGuardDuty	UnauthorizedAccess:S3/TorIPCaller
T1552.001	AmazonMacie	SensitiveData:S3Object/Credentials
T1552.001	AmazonMacie	SensitiveData:S3Object/Multiple
T1552.001	AWSCloudHSM	encrypted-volumes
T1040	AWSConfig	cloudtrail-enabled
T1552.001	AWSConfig	ec2-ebs-encryption-by-default
T1552.001	AWSConfig	encrypted-volumes
T1552.001	AWSConfig	s3-bucket-level-public-access-prohibited
T1552.001	AWSConfig	s3-bucket-public-read-prohibited
T1552.001	AWSConfig	s3-bucket-server-side-encryption-enabled
T1552.005	AmazonGuardDuty	UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
T1552.005	AWSConfig	ec2-imdsv2-check
T1562.001	AmazonGuardDuty	Exfiltration:S3/MaliciousIPCaller
T1562.001	AmazonGuardDuty	Impact:S3/MaliciousIPCaller
T1562.001	AmazonGuardDuty	PenTest:S3/KaliLinux
T1562.001	AmazonGuardDuty	PenTest:S3/ParrotLinux
T1562.001	AmazonGuardDuty	PenTest:S3/PentooLinux
T1562.001	AmazonGuardDuty	Stealth:IAMUser/CloudTrailLoggingDisabled
T1562.001	AmazonGuardDuty	Stealth:IAMUser/PasswordPolicyChange
T1562.001	AmazonGuardDuty	Stealth:S3/ServerAccessLoggingDisabled
T1562.001	AmazonGuardDuty	UnauthorizedAccess:S3/MaliciousIPCaller.Custom
T1562.001	AmazonGuardDuty	UnauthorizedAccess:S3/TorIPCaller
T1562.001	AWSSecurityHub	3.10 Ensure a log metric filter and alarm exist for security group changes
T1562.001	AWSSecurityHub	3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) 
T1562.001	AWSSecurityHub	3.12 Ensure a log metric filter and alarm exist for changes to network gateways 
T1562.001	AWSSecurityHub	3.13 Ensure a log metric filter and alarm exist for route table changes
T1562.001	AWSSecurityHub	3.14 Ensure a log metric filter and alarm exist for VPC changes
T1562.001	AWSSecurityHub	3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes
T1562.001	AWSSecurityHub	3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes
T1562.007	AWSConfig	api-gw-associated-with-waf
T1562.007	AWSConfig	ec2-security-group-attached-to-eni
T1562.007	AWSConfig	internet-gateway-authorized-vpc-only
T1562.007	AWSConfig	subnet-auto-assign-public-ip-disabled
T1562.007	AWSConfig	vpc-sg-open-only-to-authorized-ports
T1562.007	AWSSecurityHub	3.10 Ensure a log metric filter and alarm exist for security group changes
T1562.007	AWSSecurityHub	3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) 
T1562.007	AWSSecurityHub	3.12 Ensure a log metric filter and alarm exist for changes to network gateways 
T1562.007	AWSSecurityHub	3.13 Ensure a log metric filter and alarm exist for route table changes
T1562.007	AWSSecurityHub	3.14 Ensure a log metric filter and alarm exist for VPC changes
T1562.007	AWSSecurityHub	3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes
T1562.007	AWSSecurityHub	3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes
T1562.008	AmazonGuardDuty	Exfiltration:S3/MaliciousIPCaller
T1562.008	AmazonGuardDuty	Impact:S3/MaliciousIPCaller
T1562.008	AmazonGuardDuty	PenTest:S3/KaliLinux
T1562.008	AmazonGuardDuty	PenTest:S3/ParrotLinux
T1562.008	AmazonGuardDuty	PenTest:S3/PentooLinux
T1562.008	AmazonGuardDuty	Stealth:IAMUser/CloudTrailLoggingDisabled
T1562.008	AmazonGuardDuty	Stealth:IAMUser/PasswordPolicyChange
T1562.008	AmazonGuardDuty	Stealth:S3/ServerAccessLoggingDisabled
T1562.008	AmazonGuardDuty	UnauthorizedAccess:S3/MaliciousIPCaller.Custom
T1562.008	AmazonGuardDuty	UnauthorizedAccess:S3/TorIPCaller
T1562.008	AWSConfig	api-gw-execution-logging-enabled
T1562.008	AWSConfig	cloud-trail-cloud-watch-logs-enabled
T1562.008	AWSConfig	cloudtrail-s3-dataevents-enabled
T1562.008	AWSConfig	cloudtrail-security-trail-enabled
T1562.008	AWSConfig	elasticsearch-logs-to-cloudwatch
T1562.008	AWSConfig	elb-logging-enabled
T1562.008	AWSConfig	rds-logging-enabled
T1562.008	AWSConfig	redshift-cluster-configuration-check
T1562.008	AWSConfig	s3-bucket-logging-enabled 
T1562.008	AWSConfig	vpc-flow-logs-enabled
T1562.008	AWSConfig	wafv2-logging-enabled
T1562.008	AWSIOTDeviceDefender	LOGGING_DISABLED_CHECK
T1562.008	AWSSecurityHub	3.10 Ensure a log metric filter and alarm exist for security group changes
T1562.008	AWSSecurityHub	3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) 
T1562.008	AWSSecurityHub	3.12 Ensure a log metric filter and alarm exist for changes to network gateways 
T1562.008	AWSSecurityHub	3.13 Ensure a log metric filter and alarm exist for route table changes
T1562.008	AWSSecurityHub	3.14 Ensure a log metric filter and alarm exist for VPC changes
T1562.008	AWSSecurityHub	3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes
T1562.008	AWSSecurityHub	3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes
T1566	AmazonGuardDuty	Trojan:EC2/PhishingDomainRequest!DNS
T1580	AmazonGuardDuty	Discovery:IAMUser/AnomalousBehavior
T1580	AmazonGuardDuty	Discovery:S3/MaliciousIPCaller
T1580	AmazonGuardDuty	Discovery:S3/MaliciousIPCaller.Custom
T1580	AmazonGuardDuty	Discovery:S3/TorIPCaller
T1580	AmazonGuardDuty	PenTest:IAMUser/KaliLinux
T1580	AmazonGuardDuty	PenTest:IAMUser/ParrotLinux
T1580	AmazonGuardDuty	PenTest:IAMUser/PentooLinux
T1580	AmazonGuardDuty	PenTest:S3/KaliLinux
T1580	AmazonGuardDuty	PenTest:S3/ParrotLinux
T1580	AmazonGuardDuty	PenTest:S3/PentooLinux
T1580	AWSOrganizations	Discovery:IAMUser/AnomalousBehavior
T1580	AWSSecurityHub	3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes 
T1580	AWSSecurityHub	EC2 instances that are open to the Internet
T1580	AWSSecurityHub	EC2 instances that have ports accessible from the Internet
T1580	AWSSecurityHub	S3 buckets with public write or read permissions
T1619	AmazonGuardDuty	Discovery:S3/MaliciousIPCaller
T1621	AmazonGuardDuty	UnauthorizedAccess:IAMUser/ConsoleLogin
T1046	AWSConfig	elbv2-acm-certificate-required
T1078.004	AWSConfig	elbv2-acm-certificate-required
T1098	AWSConfig	elbv2-acm-certificate-required
T1098.001	AWSConfig	elbv2-acm-certificate-required
T1098.004	AWSConfig	elbv2-acm-certificate-required
T1190	AWSConfig	elbv2-acm-certificate-required
T1199	AWSConfig	elbv2-acm-certificate-required
T1528	AWSConfig	elbv2-acm-certificate-required
T1550.001	AWSConfig	elbv2-acm-certificate-required
T1498.001	AWSConfig	lambda-concurrency-check
T1498.002	AWSConfig	lambda-concurrency-check
T1499.002	AWSConfig	lambda-concurrency-check
T1499.003	AWSConfig	lambda-concurrency-check
T1499.004	AWSConfig	lambda-concurrency-check
T1552	AWSConfig	alb-http-drop-invalid-header-enabled
T1110.004	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1530	AWSConfig	cloudwatch-log-group-encrypted
T1552.001	AWSConfig	codebuild-project-source-repo-url-check
T1552.001	AWSConfig	alb-http-drop-invalid-header-enabled
T1190	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1110.001	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1485	AWSConfig	cmk-backing-key-rotation-enabled
T1040	AWSConfig	alb-http-drop-invalid-header-enabled
T1078	AWSConfig	codebuild-project-envvar-awscred-check
T1552	AWSConfig	codebuild-project-source-repo-url-check
T1550.001	AWSConfig	cloudwatch-log-group-encrypted
T1078.001	AWSConfig	codebuild-project-source-repo-url-check
T1078	AWSConfig	codebuild-project-source-repo-url-check
T1552	AWSConfig	api-gw-cache-enabled-and-encrypted
T1078.004	AWSConfig	codebuild-project-envvar-awscred-check
T1550.001	AWSConfig	alb-http-drop-invalid-header-enabled
T1552	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1528	AWSConfig	alb-http-drop-invalid-header-enabled
T1552	AWSConfig	codebuild-project-envvar-awscred-check
T1552	AWSConfig	ssm-document-not-public
T1562.007	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1528	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1550.001	AWSConfig	codebuild-project-source-repo-url-check
T1530	AWSConfig	api-gw-cache-enabled-and-encrypted
T1525	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1552.001	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1110.002	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1204.003	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1078.004	AWSConfig	codebuild-project-source-repo-url-check
T1189	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1562.008	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1562.001	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1119	AWSConfig	api-gw-cache-enabled-and-encrypted
T1552.005	AWSConfig	ssm-document-not-public
T1119	AWSConfig	cloudwatch-log-group-encrypted
T1552.005	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1550.001	AWSConfig	api-gw-cache-enabled-and-encrypted
T1552	AWSConfig	cloudwatch-log-group-encrypted
T1552.001	AWSConfig	ssm-document-not-public
T1552.001	AWSConfig	codebuild-project-envvar-awscred-check
T1110.003	AWSConfig	ec2-managedinstance-patch-compliance-status-check
T1078.001	AWSConfig	codebuild-project-envvar-awscred-check
T1098.001	AWSConfig	opensearch-access-control-enabled
MITRE	servicio	Rule
T1562.001	AWSConfig	ecs-containers-nonprivileged
T1087.004	AWSConfig	efs-access-point-enforce-root-directory
T1078.004	AWSConfig	emr-kerberos-enabled
T1525	AWSConfig	ecs-containers-nonprivileged
T1526	AWSConfig	ecs-containers-readonly-access
T1110.001	AWSConfig	emr-kerberos-enabled
T1110.004	AWSConfig	emr-kerberos-enabled
T1580	AWSConfig	efs-access-point-enforce-root-directory
T1530	AWSConfig	s3-bucket-acl-prohibited
T1087.004	AWSConfig	emr-kerberos-enabled
T1580	AWSConfig	efs-access-point-enforce-user-identity
T1562.008	AWSConfig	ecs-containers-nonprivileged
T1562.008	AWSConfig	ecs-containers-readonly-access
T1580	AWSConfig	ecs-containers-nonprivileged
T1552.001	AWSConfig	ecs-containers-nonprivileged
T1098.001	AWSConfig	efs-access-point-enforce-root-directory
T1552.001	AWSConfig	efs-access-point-enforce-root-directory
T1562.007	AWSConfig	ecs-containers-readonly-access
T1087.004	AWSConfig	efs-access-point-enforce-user-identity
T1562.001	AWSConfig	ecs-containers-readonly-access
T1098.004	AWSConfig	efs-access-point-enforce-root-directory
T1580	AWSConfig	opensearch-access-control-enabled
T1525	AWSConfig	ecs-containers-readonly-access
T1528	AWSConfig	ecs-containers-nonprivileged
T1530	AWSConfig	opensearch-access-control-enabled
T1087.004	AWSConfig	opensearch-access-control-enabled
T1098.001	AWSConfig	emr-kerberos-enabled
T1040	AWSConfig	efs-access-point-enforce-root-directory
T1580	AWSConfig	ecs-containers-readonly-access
T1110.003	AWSConfig	emr-kerberos-enabled
T1538	AWSConfig	opensearch-access-control-enabled
T1098.004	AWSConfig	emr-kerberos-enabled
T1528	AWSConfig	ecs-containers-readonly-access
T1537	AWSConfig	s3-bucket-acl-prohibited
T1562.007	AWSConfig	ecs-containers-nonprivileged
T1526	AWSConfig	opensearch-access-control-enabled
T1098.004	AWSConfig	opensearch-access-control-enabled
T1078.004	AWSConfig	opensearch-access-control-enabled
T1528	AWSConfig	efs-access-point-enforce-root-directory
T1040	AWSConfig	efs-access-point-enforce-user-identity
T1528	AWSConfig	efs-access-point-enforce-user-identity
T1552.001	AWSConfig	efs-access-point-enforce-user-identity
T1526	AWSConfig	ecs-containers-nonprivileged
T1578.002	AWSConfig	multi-region-cloudtrail-enabled
T1578.004	AWSConfig	multi-region-cloudtrail-enabled
T1578.003	AWSConfig	multi-region-cloudtrail-enabled
T1526	AWSConfig	multi-region-cloudtrail-enabled
T1496	AWSConfig	multi-region-cloudtrail-enabled
T1578	AWSConfig	multi-region-cloudtrail-enabled
T1046	AWSConfig	securityhub-enabled
T1531	AWSConfig	multi-region-cloudtrail-enabled
T1578.001	AWSConfig	multi-region-cloudtrail-enabled
T1491.002	AWSConfig	autoscaling-launch-config-public-ip-disabled
T1562.001	AWSConfig	cloudtrail-enabled
T1136.003	AWSConfig	cloudtrail-enabled
T1578.003	AWSConfig	cloud-trail-log-file-validation-enabled
T1552.001	AWSConfig	cloudtrail-enabled
T1189	AWSConfig	ec2-instance-managed-by-systems-manager
T1190	AWSConfig	ec2-instance-managed-by-systems-manager
T1110.004	AWSConfig	cloudtrail-enabled
T1498.001	AWSConfig	autoscaling-group-elb-healthcheck-required
T1204.003	AWSConfig	restricted-ssh
T1078.001	AWSConfig	ebs-snapshot-public-restorable-check
T1189	AWSConfig	cloud-trail-log-file-validation-enabled
T1562.007	AWSConfig	ec2-instances-in-vpc
T1110.002	AWSConfig	cloudtrail-enabled
T1201	AWSConfig	cloud-trail-encryption-enabled
T1550.001	AWSConfig	ec2-instance-managed-by-systems-manager
T1530	AWSConfig	cloudtrail-enabled
T1199	AWSConfig	alb-waf-enabled
T1110.001	AWSConfig	restricted-ssh
T1562	AWSConfig	restricted-ssh
T1525	AWSConfig	ec2-instance-managed-by-systems-manager
T1552	AWSConfig	cloud-trail-encryption-enabled
T1040	AWSConfig	restricted-common-ports
T1499.004	AWSConfig	beanstalk-enhanced-health-reporting-enabled
T1498.002	AWSConfig	beanstalk-enhanced-health-reporting-enabled
T1499.002	AWSConfig	cloudtrail-enabled
T1562.001	AWSConfig	restricted-ssh
T1537	AWSConfig	cloudtrail-enabled
T1580	AWSConfig	cloudtrail-enabled
T1528	AWSConfig	cloud-trail-encryption-enabled
T1562.008	AWSConfig	ec2-instances-in-vpc
T1537	AWSConfig	ec2-instances-in-vpc
T1098	AWSConfig	cloud-trail-log-file-validation-enabled
T1204.003	AWSConfig	ebs-snapshot-public-restorable-check
T1098	AWSConfig	cloudtrail-enabled
T1552.001	AWSConfig	ec2-instance-managed-by-systems-manager
T1485	AWSConfig	cloudtrail-enabled
T1046	AWSConfig	restricted-common-ports
T1499.003	AWSConfig	alb-waf-enabled
T1190	AWSConfig	ec2-instances-in-vpc
T1566	AWSConfig	cloudtrail-enabled
T1119	AWSConfig	rds-multi-az-support
T1190	AWSConfig	cloudtrail-enabled
T1098.004	AWSConfig	cloud-trail-log-file-validation-enabled
T1499.002	AWSConfig	autoscaling-launch-config-public-ip-disabled
T1578.001	AWSConfig	cloud-trail-log-file-validation-enabled
T1530	AWSConfig	ebs-snapshot-public-restorable-check
T1046	AWSConfig	alb-waf-enabled
T1498.002	AWSConfig	autoscaling-launch-config-public-ip-disabled
T1110.003	AWSConfig	cloudtrail-enabled
T1136	AWSConfig	cloud-trail-log-file-validation-enabled
T1204.003	AWSConfig	cloud-trail-encryption-enabled
T1562.008	AWSConfig	cloudtrail-enabled
T1485	AWSConfig	rds-multi-az-support
T1190	AWSConfig	autoscaling-launch-config-public-ip-disabled
T1499.004	AWSConfig	alb-waf-enabled
T1499.002	AWSConfig	beanstalk-enhanced-health-reporting-enabled
T1201	AWSConfig	cloudtrail-enabled
T1498.001	AWSConfig	alb-waf-enabled
T1098.004	AWSConfig	cloudtrail-enabled
T1110.001	AWSConfig	cloudtrail-enabled
T1040	AWSConfig	ec2-instances-in-vpc
T1528	AWSConfig	ebs-snapshot-public-restorable-check
T1190	AWSConfig	restricted-ssh
T1485	AWSConfig	ec2-instances-in-vpc
T1110	AWSConfig	restricted-ssh
T1580	AWSConfig	cloud-trail-encryption-enabled
T1098.001	AWSConfig	cloud-trail-log-file-validation-enabled
T1486	AWSConfig	ec2-instances-in-vpc
T1498.001	AWSConfig	autoscaling-launch-config-public-ip-disabled
T1098.004	AWSConfig	ec2-instance-managed-by-systems-manager
T1498.002	AWSConfig	cloudtrail-enabled
T1087.004	AWSConfig	cloudtrail-enabled
T1562.007	AWSConfig	restricted-ssh
T1499.003	AWSConfig	beanstalk-enhanced-health-reporting-enabled
T1498.001	AWSConfig	ec2-instances-in-vpc
T1110.004	AWSConfig	restricted-ssh
T1491.002	AWSConfig	cloudtrail-enabled
T1578	AWSConfig	cloud-trail-log-file-validation-enabled
T1498.001	AWSConfig	cloudtrail-enabled
T1110.003	AWSConfig	restricted-ssh
T1189	AWSConfig	ec2-instances-in-vpc
T1550.001	AWSConfig	cloudtrail-enabled
T1562	AWSConfig	ec2-instances-in-vpc
T1499.004	AWSConfig	autoscaling-launch-config-public-ip-disabled
T1499.003	AWSConfig	cloudtrail-enabled
T1498.002	AWSConfig	autoscaling-group-elb-healthcheck-required
T1119	AWSConfig	cloudtrail-enabled
T1499.002	AWSConfig	alb-waf-enabled
T1499.004	AWSConfig	cloudtrail-enabled
T1552.005	AWSConfig	cloudtrail-enabled
T1498.002	AWSConfig	ec2-instances-in-vpc
T1046	AWSConfig	ec2-instances-in-vpc
T1486	AWSConfig	rds-multi-az-support
T1562.001	AWSConfig	ec2-instances-in-vpc
T1562.007	AWSConfig	cloudtrail-enabled
T1119	AWSConfig	ec2-instances-in-vpc
T1204.003	AWSConfig	cloudtrail-enabled
T1486	AWSConfig	cloud-trail-log-file-validation-enabled
T1491.002	AWSConfig	rds-multi-az-support
T1201	AWSConfig	restricted-ssh
T1498.001	AWSConfig	beanstalk-enhanced-health-reporting-enabled
T1189	AWSConfig	cloudtrail-enabled
T1098.001	AWSConfig	cloudtrail-enabled
T1485	AWSConfig	cloud-trail-log-file-validation-enabled
T1078.004	AWSConfig	ebs-snapshot-public-restorable-check
T1189	AWSConfig	alb-waf-enabled
T1525	AWSConfig	cloudtrail-enabled
T1578.002	AWSConfig	cloud-trail-log-file-validation-enabled
T1199	AWSConfig	cloudtrail-enabled
T1498.002	AWSConfig	alb-waf-enabled
T1087.004	AWSConfig	ebs-snapshot-public-restorable-check
T1046	AWSConfig	cloudtrail-enabled
T1552	AWSConfig	cloudtrail-enabled
T1528	AWSConfig	cloudtrail-enabled
T1499.004	AWSConfig	autoscaling-group-elb-healthcheck-required
T1491.002	AWSConfig	ec2-instance-managed-by-systems-manager
T1087.004	AWSConfig	cloud-trail-encryption-enabled
T1190	AWSConfig	alb-waf-enabled
T1486	AWSConfig	cloudtrail-enabled
T1538	AWSConfig	cloudtrail-enabled
T1499.003	AWSConfig	autoscaling-launch-config-public-ip-disabled
T1078.001	AWSConfig	cloudtrail-enabled
T1499.002	AWSConfig	autoscaling-group-elb-healthcheck-required
T1189	AWSConfig	restricted-ssh
T1078.004	AWSConfig	cloudtrail-enabled
T1136.003	AWSConfig	cloud-trail-log-file-validation-enabled
T1204.003	AWSConfig	ec2-instance-managed-by-systems-manager
T1499.003	AWSConfig	autoscaling-group-elb-healthcheck-required
\.


                                                                                                                                                                                                                                                                                 4450.dat                                                                                            0000600 0004000 0002000 00000002577 14362250175 0014266 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        T1189	KOS-02
T1189	RB-05
T1190	RB-05
T1190	RB-21
T1190	RB-22
T1190	IDM-01
T1190	KOS-01
T1190	RB-23
T1566	KOS-02
T1566	RB-05
T1566	HR-03
T1566	RB-23
T1199	IDM-01
T1199	RB-23
T1078.001	IDM-11
T1078.004	IDM-11
T1078.004	HR-03
T1078.004	IDM-01
T1078.004	IDM-08
T1204.003	HR-03
T1204.003	KOS-01
T1098.001	IDM-01
T1098.001	IDM-08
T1098.001	RB-23
T1098.004	IDM-01
T1098.004	IDM-02
T1098.004	RB-22
T1136.003	IDM-01
T1136.003	IDM-08
T1136.003	RB-23
T1525	IDM-01
T1525	HR-03
T1562.001	IDM-01
T1562.001	IDM-06
T1562.007	IDM-01
T1562.007	IDM-06
T1562.008	IDM-01
T1562.008	IDM-06
T1550.001	KRY-02
T1550.001	IDM-12
T1110.001	IDM-01
T1110.001	IDM-08
T1110.001	IDM-11
T1110.001	RB-22
T1110.002	IDM-08
T1110.002	IDM-11
T1110.003	IDM-01
T1110.003	IDM-08
T1110.003	IDM-11
T1110.004	IDM-01
T1110.004	IDM-08
T1110.004	IDM-11
T1110.004	RB-22
T1040	IDM-01
T1040	IDM-08
T1528	HR-03
T1528	IDM-12
T1528	IDM-01
T1552.001	HR-03
T1552.001	IDM-01
T1552.001	IDM-11
T1552.005	RB-22
T1552.005	RB-23
T1087.004	IDM-01
T1580	IDM-01
T1538	IDM-01
T1538	IDM-12
T1526	IDM-01
T1046	RB-22
T1046	RB-23
T1046	IDM-12
T1040	KRY-02
T1119	KRY-02
T1119	KRY-03
T1530	IDM-01
T1530	IDM-08
T1530	RB-23
T1530	KRY-03
T1537	IDM-01
T1537	IDM-11
T1537	KOS-03
T1531	IDM-06
T1531	IDM-12
T1485	RB-06
T1486	RB-06
T1491.002	RB-06
T1499.002	KOS-01
T1499.003	KOS-01
T1499.004	KOS-01
T1498.001	KOS-01
T1498.002	KOS-01
T1496	RB-22
T1496	RB-23
T1648	IDM-01
T1648	KOS-01
\.


                                                                                                                                 4451.dat                                                                                            0000600 0004000 0002000 00000015656 14362250175 0014271 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        T1078.001	5.6
T1078.004	5.6
T1087.004	5.6
T1098.001	5.6
T1110.001	5.6
T1110.002	5.6
T1110.003	5.6
T1110.004	5.6
T1136.003	5.6
T1190	5.6
T1525	5.6
T1528	5.6
T1530	5.6
T1537	5.6
T1538	5.6
T1552.001	5.6
T1562.001	5.6
T1562.007	5.6
T1562.008	5.6
T1580	5.6
T1078.001	6.7
T1078.004	6.7
T1087.004	6.7
T1098.001	6.7
T1110.001	6.7
T1110.002	6.7
T1110.003	6.7
T1110.004	6.7
T1136.003	6.7
T1190	6.7
T1525	6.7
T1528	6.7
T1530	6.7
T1537	6.7
T1538	6.7
T1552.001	6.7
T1562.001	6.7
T1562.007	6.7
T1562.008	6.7
T1580	6.7
T1078.004	15.2
T1098.001	15.2
T1110.001	15.2
T1110.002	15.2
T1110.003	15.2
T1110.004	15.2
T1119	15.2
T1136.003	15.2
T1530	15.2
T1537	15.2
T1550.001	15.2
T1552.005	15.2
T1078.004	15.3
T1098.001	15.3
T1110.001	15.3
T1110.002	15.3
T1110.003	15.3
T1110.004	15.3
T1119	15.3
T1136.003	15.3
T1530	15.3
T1537	15.3
T1550.001	15.3
T1552.005	15.3
T1078.004	15.5
T1098.001	15.5
T1110.001	15.5
T1110.002	15.5
T1110.003	15.5
T1110.004	15.5
T1119	15.5
T1136.003	15.5
T1530	15.5
T1537	15.5
T1550.001	15.5
T1552.005	15.5
T1078.004	4.11
T1098.001	4.11
T1110.001	4.11
T1110.002	4.11
T1110.003	4.11
T1110.004	4.11
T1136.003	4.11
T1537	4.11
T1552.005	4.11
T1098.004	6.7
T1199	6.7
T1485	6.7
T1486	6.7
T1491.002	6.7
T1498.001	6.7
T1498.002	6.7
T1499.002	6.7
T1499.003	6.7
T1499.004	6.7
T1552.005	6.7
T1046	3.8
T1098.001	3.8
T1136.003	3.8
T1189	3.8
T1190	3.8
T1199	3.8
T1204.003	3.8
T1498.001	3.8
T1498.002	3.8
T1499.002	3.8
T1499.003	3.8
T1499.004	3.8
T1528	3.8
T1530	3.8
T1537	3.8
T1552.001	3.8
T1552.005	3.8
T1566	3.8
T1078.001	3.14
T1078.004	3.14
T1087.004	3.14
T1098.001	3.14
T1110.001	3.14
T1110.002	3.14
T1110.003	3.14
T1110.004	3.14
T1136.003	3.14
T1189	3.14
T1190	3.14
T1199	3.14
T1485	3.14
T1486	3.14
T1491.002	3.14
T1525	3.14
T1528	3.14
T1530	3.14
T1537	3.14
T1538	3.14
T1552.001	3.14
T1562.001	3.14
T1562.007	3.14
T1562.008	3.14
T1580	3.14
T1110.001	4.10
T1110.002	4.10
T1110.003	4.10
T1110.004	4.10
T1204	14.7
T1528	14.7
T1552	14.7
T1552.001	14.7
T1566	14.7
T1204	14.8
T1528	14.8
T1552	14.8
T1552.001	14.8
T1566	14.8
T1040	8.10
T1552	8.10
T1552.001	8.10
T1562.008	8.12
T1562.008	8.6
T1562.008	8.7
T1562.008	8.8
T1190	8.4
T1552	8.4
T1552.005	8.4
T1562.008	8.4
T1046	3.13
T1078.001	3.13
T1078.004	3.13
T1110.001	3.13
T1110.002	3.13
T1110.003	3.13
T1110.004	3.13
T1189	3.13
T1190	3.13
T1201	3.13
T1204.003	3.13
T1498.001	3.13
T1498.002	3.13
T1499.002	3.13
T1499.003	3.13
T1499.004	3.13
T1528	3.13
T1530	3.13
T1537	3.13
T1552.001	3.13
T1552.005	3.13
T1562.001	3.13
T1566	3.13
T1046	12.3
T1078.004	12.3
T1098	12.3
T1098.001	12.3
T1098.004	12.3
T1110.001	12.3
T1110.002	12.3
T1110.003	12.3
T1110.004	12.3
T1119	12.3
T1136.003	12.3
T1189	12.3
T1190	12.3
T1199	12.3
T1201	12.3
T1204.003	12.3
T1498.001	12.3
T1498.002	12.3
T1499.002	12.3
T1499.003	12.3
T1499.004	12.3
T1525	12.3
T1528	12.3
T1530	12.3
T1537	12.3
T1550.001	12.3
T1552.001	12.3
T1552.005	12.3
T1562.001	12.3
T1566	12.3
T1046	16.7
T1078.004	16.7
T1098	16.7
T1098.001	16.7
T1098.004	16.7
T1110.001	16.7
T1110.002	16.7
T1110.003	16.7
T1110.004	16.7
T1119	16.7
T1136.003	16.7
T1189	16.7
T1190	16.7
T1199	16.7
T1201	16.7
T1204.003	16.7
T1498.001	16.7
T1498.002	16.7
T1499.002	16.7
T1499.003	16.7
T1499.004	16.7
T1525	16.7
T1528	16.7
T1530	16.7
T1537	16.7
T1550.001	16.7
T1552.001	16.7
T1552.005	16.7
T1562.001	16.7
T1566	16.7
T1562.007	12.3
T1562.008	12.3
T1562.007	16.7
T1562.008	16.7
T1046	1.5
T1098.004	1.5
T1119	1.5
T1189	1.5
T1190	1.5
T1530	1.5
T1046	6.6
T1098.004	6.6
T1119	6.6
T1189	6.6
T1190	6.6
T1530	6.6
T1078	3.10
T1078.004	3.10
T1098.001	3.10
T1110.001	3.10
T1110.002	3.10
T1110.003	3.10
T1110.004	3.10
T1136.003	3.10
T1528	3.10
T1552.001	3.10
T1087.004	6.6
T1528	6.6
T1537	6.6
T1538	6.6
T1190	17.8
T1552	17.8
T1552.005	17.8
T1046	12.4
T1098	12.4
T1098.001	12.4
T1136	12.4
T1136.003	12.4
T1190	12.4
T1199	12.4
T1046	16.10
T1098	16.10
T1098.001	16.10
T1136	16.10
T1136.003	16.10
T1190	16.10
T1199	16.10
T1552	12.4
T1552.001	12.4
T1552	3.7
T1552.001	3.7
T1046	16.6
T1078	16.6
T1098.004	16.6
T1190	16.6
T1204.003	16.6
T1525	16.6
T1528	16.6
T1530	16.6
T1552.001	16.6
T1562.001	16.6
T1562.007	16.6
T1562.008	16.6
T1078	15.4
T1078.001	15.4
T1078.004	15.4
T1078	16.10
T1078.001	16.10
T1078.004	16.10
T1189	4.12
T1190	4.12
T1040	3.13
T1119	3.13
T1046	9.5
T1098.001	9.5
T1136.003	9.5
T1189	9.5
T1190	9.5
T1199	9.5
T1204.003	9.5
T1498.001	9.5
T1498.002	9.5
T1499.002	9.5
T1499.003	9.5
T1499.004	9.5
T1530	9.5
T1537	9.5
T1552.001	9.5
T1552.005	9.5
T1566	9.5
T1046	13.10
T1098.001	13.10
T1136.003	13.10
T1189	13.10
T1190	13.10
T1199	13.10
T1204.003	13.10
T1498.001	13.10
T1498.002	13.10
T1499.002	13.10
T1499.003	13.10
T1499.004	13.10
T1530	13.10
T1537	13.10
T1552.001	13.10
T1552.005	13.10
T1566	13.10
T1046	10.4
T1098.004	10.4
T1189	10.4
T1190	10.4
T1201	10.4
T1204.003	10.4
T1485	10.4
T1486	10.4
T1491.002	10.4
T1525	10.4
T1562.001	10.4
T1566	10.4
T1046	10.6
T1098.004	10.6
T1189	10.6
T1190	10.6
T1201	10.6
T1204.003	10.6
T1485	10.6
T1486	10.6
T1491.002	10.6
T1525	10.6
T1562.001	10.6
T1566	10.6
T1040	1.3
T1046	1.3
T1078.001	1.3
T1078.004	1.3
T1098	1.3
T1098.001	1.3
T1098.004	1.3
T1110.001	1.3
T1110.002	1.3
T1110.003	1.3
T1110.004	1.3
T1119	1.3
T1136.003	1.3
T1189	1.3
T1190	1.3
T1201	1.3
T1204.003	1.3
T1485	1.3
T1486	1.3
T1491.002	1.3
T1499.002	1.3
T1499.003	1.3
T1499.004	1.3
T1525	1.3
T1528	1.3
T1530	1.3
T1537	1.3
T1550.001	1.3
T1552.001	1.3
T1552.005	1.3
T1562.001	1.3
T1562.007	1.3
T1562.008	1.3
T1566	1.3
T1040	1.5
T1078.001	1.5
T1078.004	1.5
T1098	1.5
T1098.001	1.5
T1110.001	1.5
T1110.002	1.5
T1110.003	1.5
T1110.004	1.5
T1136.003	1.5
T1201	1.5
T1204.003	1.5
T1485	1.5
T1486	1.5
T1491.002	1.5
T1499.002	1.5
T1499.003	1.5
T1499.004	1.5
T1525	1.5
T1528	1.5
T1537	1.5
T1550.001	1.5
T1552.001	1.5
T1552.005	1.5
T1562.001	1.5
T1562.007	1.5
T1562.008	1.5
T1566	1.5
T1040	13.11
T1046	13.11
T1078.001	13.11
T1078.004	13.11
T1098	13.11
T1098.001	13.11
T1098.004	13.11
T1110.001	13.11
T1110.002	13.11
T1110.003	13.11
T1110.004	13.11
T1119	13.11
T1136.003	13.11
T1189	13.11
T1190	13.11
T1201	13.11
T1204.003	13.11
T1485	13.11
T1486	13.11
T1491.002	13.11
T1499.002	13.11
T1499.003	13.11
T1499.004	13.11
T1525	13.11
T1528	13.11
T1530	13.11
T1537	13.11
T1550.001	13.11
T1552.001	13.11
T1552.005	13.11
T1562.001	13.11
T1562.007	13.11
T1562.008	13.11
T1566	13.11
T1040	13.6
T1046	13.6
T1078.001	13.6
T1078.004	13.6
T1098	13.6
T1098.001	13.6
T1098.004	13.6
T1110.001	13.6
T1110.002	13.6
T1110.003	13.6
T1110.004	13.6
T1119	13.6
T1136.003	13.6
T1189	13.6
T1190	13.6
T1201	13.6
T1204.003	13.6
T1485	13.6
T1486	13.6
T1491.002	13.6
T1499.002	13.6
T1499.003	13.6
T1499.004	13.6
T1525	13.6
T1528	13.6
T1530	13.6
T1537	13.6
T1550.001	13.6
T1552.001	13.6
T1552.005	13.6
T1562.001	13.6
T1562.007	13.6
T1562.008	13.6
T1566	13.6
T1040	15.5
T1046	15.5
T1078.001	15.5
T1098	15.5
T1098.004	15.5
T1189	15.5
T1190	15.5
T1201	15.5
T1204.003	15.5
T1485	15.5
T1486	15.5
T1491.002	15.5
T1499.002	15.5
T1499.003	15.5
T1499.004	15.5
T1525	15.5
T1528	15.5
T1552.001	15.5
T1562.001	15.5
T1562.007	15.5
T1562.008	15.5
T1566	15.5
T1199	3.5
T1204.003	15.3
T1204.003	15.4
T1078	15.2
T1204.003	15.2
T1078	15.6
T1204.003	15.6
T1648	3.8
T1648	1.3
T1648	13.11
T1648	13.6
\.


                                                                                  4448.dat                                                                                            0000600 0004000 0002000 00000002102 14362250175 0014255 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        TA0002	T1204
TA0002	T1204.003
TA0003	T1078
TA0003	T1078.001
TA0003	T1078.004
TA0003	T1098
TA0003	T1098.001
TA0003	T1098.004
TA0003	T1136
TA0003	T1136.003
TA0003	T1525
TA0004	T1078
TA0004	T1078.001
TA0004	T1078.004
TA0005	T1078
TA0005	T1078.001
TA0005	T1078.004
TA0005	T1535
TA0001	T1566
TA0005	T1550
TA0005	T1550.001
TA0005	T1562
TA0005	T1562.001
TA0005	T1562.007
TA0005	T1562.008
TA0005	T1578
TA0005	T1578.001
TA0005	T1578.002
TA0005	T1578.003
TA0005	T1578.004
TA0006	T1040
TA0006	T1110
TA0006	T1110.001
TA0006	T1110.002
TA0006	T1110.003
TA0006	T1110.004
TA0006	T1528
TA0006	T1552
TA0006	T1552.001
TA0006	T1552.005
TA0006	T1621
TA0007	T1040
TA0007	T1046
TA0007	T1087.004
TA0007	T1201
TA0007	T1526
TA0007	T1538
TA0007	T1580
TA0007	T1619
TA0008	T1550
TA0008	T1550.001
TA0009	T1119
TA0009	T1530
TA0010	T1537
TA0040	T1485
TA0040	T1486
TA0040	T1491
TA0040	T1491.002
TA0040	T1496
TA0040	T1498
TA0040	T1498.001
TA0040	T1498.002
TA0040	T1499.002
TA0040	T1499.003
TA0040	T1499.004
TA0040	T1531
TA0001	T1078
TA0001	T1078.001
TA0001	T1078.004
TA0001	T1189
TA0001	T1190
TA0001	T1199
TA0002	T1648
\.


                                                                                                                                                                                                                                                                                                                                                                                                                                                              4452.dat                                                                                            0000600 0004000 0002000 00000003604 14362250175 0014260 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        T1040	mp.com.2
T1040	mp.com.3
T1040	op.acc.6
T1040	op.acc.4
T1046	op.mon.1
T1046	mp.com.4
T1078	op.acc.4
T1078	op.exp.2
T1078	mp.per.3
T1078.001	op.exp.2
T1078.004	op.acc.4
T1078.004	op.exp.2
T1078.004	mp.per.3
T1087.004	op.acc.4
T1087.004	op.acc.3
T1098	op.acc.4
T1098	mp.com.4
T1098	op.acc.3
T1098.001	mp.com.4
T1098.001	op.acc.4
T1098.001	op.exp.2
T1098.004	op.exp.2
T1098.004	op.acc.2
T1110	op.exp.2
T1110	op.acc.2
T1110	op.acc.4
T1110.001	op.acc.4
T1110.002	op.acc.4
T1110.003	op.acc.4
T1110.004	op.acc.4
T1119	mp.com.2
T1136	op.acc.4
T1136	mp.com.4
T1136	op.acc.2
T1136	op.exp.2
T1136.003	op.acc.4
T1189	mp.per.3
T1189	mp.s.3
T1190	mp.com.4
T1190	mp.s.2
T1190	op.acc.3
T1190	op.exp.2
T1199	mp.com.4
T1204	mp.per.3
T1204.003	mp.sw.1
T1485	mp.info.6
T1486	mp.info.6
T1491	mp.info.6
T1491.002	mp.info.6
T1496	op.exp.8
T1498	mp.s.4
T1498.001	mp.s.4
T1498.002	mp.s.4
T1499.002	mp.s.4
T1499.003	mp.s.4
T1499.004	mp.s.4
T1525	op.exp.2
T1526	op.exp.8
T1528	mp.per.3
T1528	op.acc.2
T1530	op.acc.2
T1531	op.exp.8
T1535	op.exp.2
T1537	op.acc.3
T1537	op.acc.2
T1538	op.acc.3
T1538	op.acc.2
T1550	op.exp.2
T1550	op.acc.3
T1550	op.acc.2
T1550.001	op.exp.2
T1550.001	op.acc.3
T1550.001	op.acc.2
T1552	mp.com.2
T1552	op.exp.2
T1552	op.acc.2
T1552	op.mon.3
T1552.001	mp.com.2
T1552.005	mp.com.2
T1562	op.exp.2
T1562	op.acc.3
T1562	op.acc.2
T1562.001	op.exp.2
T1562.001	op.acc.3
T1562.001	op.acc.2
T1562.007	op.exp.2
T1562.007	op.acc.3
T1562.007	op.acc.2
T1562.008	op.exp.2
T1562.008	op.acc.3
T1562.008	op.acc.2
T1566	mp.s.3
T1578	op.exp.8
T1578	op.acc.3
T1578	op.acc.2
T1578.001	op.exp.8
T1578.001	op.acc.3
T1578.001	op.acc.2
T1578.002	op.exp.8
T1578.002	op.acc.3
T1578.002	op.acc.2
T1578.003	op.exp.8
T1578.003	op.acc.3
T1578.003	op.acc.2
T1578.004	op.exp.8
T1578.004	op.acc.3
T1578.004	op.acc.2
T1580	op.acc.3
T1580	op.acc.2
T1619	op.acc.3
T1619	op.acc.2
T1621	op.acc.4
T1621	op.acc.2
T1621	mp.per.3
T1648	op.acc.3
T1648	mp.s.4
\.


                                                                                                                            4453.dat                                                                                            0000600 0004000 0002000 00000016106 14362250176 0014263 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        T1040	SC-8
T1040	IA-2
T1040	IA-5
T1040	SI-4
T1040	AC-16
T1040	AC-17
T1040	AC-18
T1040	AC-19
T1040	SC-4
T1040	SI-7
T1040	SI-12
T1046	SC-7
T1046	SC-46
T1046	AC-4
T1046	CM-6
T1046	CM-7
T1046	CM-2
T1046	CA-7
T1046	SI-4
T1046	SI-3
T1046	CM-8
T1046	RA-5
T1078	SA-3
T1078	SA-4
T1078	SA-8
T1078	SA-10
T1078	SA-11
T1078	SA-15
T1078	SA-16
T1078	SA-17
T1078	RA-5
T1078	CA-8
T1078	SC-28
T1078	IA-5
T1078	SR-6
T1078.001	SA-3
T1078.001	SA-4
T1078.001	SA-8
T1078.001	SA-10
T1078.001	SA-11
T1078.001	SA-15
T1078.001	SA-16
T1078.001	SA-17
T1078.001	SC-28
T1078.001	AC-2
T1078.001	AC-5
T1078.001	AC-6
T1078.001	CA-7
T1078.004	SA-3
T1078.004	SA-4
T1078.004	SA-8
T1078.004	SA-10
T1078.004	SA-11
T1078.004	SA-15
T1078.004	SA-16
T1078.004	SA-17
T1078.004	SC-28
T1078.004	AC-2
T1078.004	AC-5
T1078.004	AC-6
T1078.004	CA-7
T1078.001	SI-4
T1078.004	SI-4
T1078.004	IA-2
T1078.004	IA-12
T1078.004	AC-3
T1078.004	CM-5
T1078.004	CM-6
T1078.004	AC-20
T1078.004	IA-5
T1087.004	AC-2
T1087.004	AC-3
T1087.004	AC-5
T1087.004	AC-6
T1087.004	IA-2
T1087.004	IA-8
T1098.001	IA-5
T1098.001	IA-2
T1098.001	SI-4
T1098.001	SI-7
T1098.001	SC-7
T1098.001	SC-46
T1098.001	AC-4
T1098.001	CM-7
T1098.001	AC-2
T1098.001	AC-3
T1098.001	AC-5
T1098.001	AC-6
T1098.001	AC-20
T1098.001	CM-5
T1098.001	CM-6
T1098.004	CM-2
T1098.004	CM-6
T1098.004	CM-8
T1098.004	SC-12
T1098.004	AC-3
T1098.004	RA-5
T1098.004	SI-3
T1098.004	SI-4
T1110.001	IA-2
T1110.001	IA-4
T1110.001	IA-5
T1110.001	IA-11
T1110.001	AC-2
T1110.001	AC-3
T1110.001	AC-5
T1110.001	AC-6
T1110.001	AC-7
T1110.001	AC-20
T1110.001	CA-7
T1110.001	SI-4
T1110.001	CM-2
T1110.001	CM-6
T1110.002	IA-2
T1110.002	IA-4
T1110.002	IA-5
T1110.002	IA-11
T1110.002	AC-2
T1110.002	AC-3
T1110.002	AC-5
T1110.002	AC-6
T1110.002	AC-7
T1110.002	AC-20
T1110.002	CA-7
T1110.002	SI-4
T1110.002	CM-2
T1110.002	CM-6
T1110.003	IA-2
T1110.003	IA-4
T1110.003	IA-5
T1110.003	IA-11
T1110.003	AC-2
T1110.003	AC-3
T1110.003	AC-5
T1110.003	AC-6
T1110.003	AC-7
T1110.003	AC-20
T1110.003	CA-7
T1110.003	SI-4
T1110.003	CM-2
T1110.003	CM-6
T1110.004	IA-2
T1110.004	IA-4
T1110.004	IA-5
T1110.004	IA-11
T1110.004	AC-2
T1110.004	AC-3
T1110.004	AC-5
T1110.004	AC-6
T1110.004	AC-7
T1110.004	AC-20
T1110.004	CA-7
T1110.004	SI-4
T1110.004	CM-2
T1110.004	CM-6
T1119	SI-23
T1119	SI-4
T1119	SI-7
T1119	SI-12
T1119	CP-6
T1119	CP-7
T1119	CP-9
T1119	SC-36
T1119	CM-2
T1119	CM-6
T1119	CM-8
T1119	AC-16
T1119	AC-17
T1119	AC-18
T1119	AC-19
T1119	AC-20
T1119	SC-4
T1136.003	AC-2
T1136.003	AC-3
T1136.003	AC-5
T1136.003	AC-6
T1136.003	AC-20
T1136.003	IA-2
T1136.003	IA-5
T1136.003	SI-4
T1136.003	SI-7
T1136.003	CM-5
T1136.003	CM-6
T1136.003	SC-7
T1136.003	SC-46
T1136.003	AC-4
T1136.003	CM-7
T1189	CM-2
T1189	CM-6
T1189	AC-4
T1189	AC-6
T1189	SC-2
T1189	SC-3
T1189	SC-7
T1189	SC-18
T1189	SC-29
T1189	SC-30
T1189	SC-39
T1189	CM-8
T1189	SI-3
T1189	SI-4
T1189	CA-7
T1189	SI-7
T1189	SI-2
T1189	SA-22
T1190	RA-5
T1190	RA-10
T1190	CA-2
T1190	CA-7
T1190	AC-2
T1190	AC-3
T1190	AC-4
T1190	AC-5
T1190	AC-6
T1190	CM-5
T1190	CM-6
T1190	CM-7
T1190	IA-2
T1190	IA-8
T1190	SC-46
T1190	SC-2
T1190	SC-3
T1190	SC-7
T1190	SC-18
T1190	SC-29
T1190	SC-30
T1190	SC-39
T1190	CM-8
T1190	SI-3
T1190	SI-10
T1190	SA-8
T1190	SI-4
T1190	SI-7
T1190	SI-2
T1199	SC-7
T1199	SC-46
T1199	AC-4
T1199	CM-6
T1199	CM-7
T1199	AC-3
T1199	AC-6
T1199	AC-8
T1201	CA-7
T1201	CM-2
T1201	CM-6
T1201	SI-3
T1201	SI-4
T1204.003	SI-3
T1204.003	SI-4
T1204.003	SI-8
T1204.003	CA-7
T1204.003	SC-7
T1204.003	SC-44
T1204.003	AC-4
T1204.003	CM-2
T1204.003	CM-6
T1204.003	CM-7
T1204.003	SI-2
T1204.003	SI-7
T1204.003	SR-4
T1204.003	SR-5
T1204.003	SR-6
T1204.003	SR-11
T1204.003	CA-8
T1204.003	RA-5
T1485	AC-3
T1485	AC-6
T1485	CM-2
T1485	CP-2
T1485	CP-7
T1485	CP-9
T1485	CP-10
T1485	SI-3
T1485	SI-4
T1485	SI-7
T1486	AC-3
T1486	AC-6
T1486	CM-2
T1486	CP-2
T1486	CP-6
T1486	CP-7
T1486	CP-9
T1486	CP-10
T1486	SI-3
T1486	SI-4
T1486	SI-7
T1491.002	AC-3
T1491.002	AC-6
T1491.002	CM-2
T1491.002	CP-2
T1491.002	CP-7
T1491.002	CP-9
T1491.002	CP-10
T1491.002	SI-3
T1491.002	SI-4
T1491.002	SI-7
T1498.001	AC-3
T1498.001	AC-4
T1498.001	CA-7
T1498.001	CM-6
T1498.001	CM-7
T1498.001	SC-7
T1498.001	SI-10
T1498.001	SI-15
T1498.002	AC-3
T1498.002	AC-4
T1498.002	CA-7
T1498.002	CM-6
T1498.002	CM-7
T1498.002	SC-7
T1498.002	SI-10
T1498.002	SI-15
T1499.002	AC-3
T1499.002	AC-4
T1499.002	CA-7
T1499.002	CM-6
T1499.002	CM-7
T1499.002	SC-7
T1499.002	SI-4
T1499.002	SI-10
T1499.002	SI-15
T1499.003	AC-3
T1499.003	AC-4
T1499.003	CA-7
T1499.003	CM-6
T1499.003	CM-7
T1499.003	SC-7
T1499.003	SI-4
T1499.003	SI-10
T1499.003	SI-15
T1499.004	AC-3
T1499.004	AC-4
T1499.004	CA-7
T1499.004	CM-6
T1499.004	CM-7
T1499.004	SC-7
T1499.004	SI-4
T1499.004	SI-10
T1499.004	SI-15
T1525	SI-4
T1525	AC-2
T1525	AC-3
T1525	AC-5
T1525	AC-6
T1525	CM-5
T1525	CM-6
T1525	IA-2
T1525	SI-7
T1525	IA-9
T1525	CA-8
T1525	RA-5
T1525	CM-2
T1525	CM-7
T1525	SI-2
T1525	SI-3
T1528	AC-2
T1528	AC-3
T1528	AC-4
T1528	AC-5
T1528	AC-6
T1528	AC-10
T1528	CM-2
T1528	CM-6
T1528	CM-5
T1528	CA-7
T1528	SI-4
T1528	IA-2
T1528	IA-4
T1528	IA-8
T1528	IA-5
T1528	CA-8
T1528	RA-5
T1528	SA-15
T1528	SA-11
T1530	AC-2
T1530	AC-3
T1530	AC-5
T1530	AC-6
T1530	AC-16
T1530	AC-20
T1530	AC-4
T1530	AC-7
T1530	AC-17
T1530	AC-18
T1530	AC-19
T1530	CM-5
T1530	CM-2
T1530	CM-6
T1530	CM-7
T1530	CM-8
T1530	IA-8
T1530	IA-2
T1530	IA-5
T1530	IA-3
T1530	IA-4
T1530	CA-7
T1530	CA-8
T1530	SC-28
T1530	SC-4
T1530	SC-7
T1530	SI-4
T1530	SI-10
T1530	SI-15
T1530	SI-7
T1530	SI-12
T1530	RA-5
T1530	IA-6
T1537	AC-2
T1537	AC-3
T1537	AC-4
T1537	AC-6
T1537	AC-16
T1537	AC-17
T1537	AC-20
T1537	AC-5
T1537	CM-5
T1537	CM-6
T1537	CM-7
T1537	IA-8
T1537	IA-2
T1537	IA-3
T1537	IA-4
T1537	CA-7
T1537	SI-4
T1537	SI-10
T1537	SI-15
T1537	SC-7
T1538	AC-2
T1538	AC-3
T1538	AC-5
T1538	AC-6
T1538	IA-2
T1538	IA-8
T1550.001	SC-8
T1550.001	SC-28
T1550.001	CM-2
T1550.001	CM-6
T1550.001	CM-10
T1550.001	CM-11
T1550.001	AC-16
T1550.001	AC-17
T1550.001	AC-19
T1550.001	AC-20
T1550.001	SI-4
T1550.001	SI-7
T1550.001	SI-12
T1550.001	CA-8
T1550.001	IA-2
T1550.001	IA-4
T1552.001	CM-2
T1552.001	CM-6
T1552.001	IA-2
T1552.001	AC-6
T1552.001	AC-2
T1552.001	AC-4
T1552.001	AC-5
T1552.001	CA-7
T1552.001	SC-4
T1552.001	SC-7
T1552.001	SC-12
T1552.001	SC-28
T1552.001	SI-4
T1552.001	SA-15
T1552.001	IA-5
T1552.001	CA-8
T1552.001	RA-5
T1552.001	SA-11
T1552.005	CA-7
T1552.005	CM-6
T1552.005	CM-7
T1552.005	IA-3
T1552.005	IA-4
T1552.005	SC-7
T1552.005	SI-4
T1552.005	SI-10
T1552.005	SI-15
T1552.005	AC-3
T1552.005	AC-4
T1552.005	AC-16
T1552.005	AC-20
T1562.001	CA-8
T1562.001	RA-5
T1562.001	CM-2
T1562.001	IA-2
T1562.001	IA-4
T1562.001	SI-4
T1562.007	CA-8
T1562.007	RA-5
T1562.007	CM-2
T1562.007	IA-2
T1562.007	IA-4
T1562.007	SI-4
T1562.008	CA-8
T1562.008	RA-5
T1562.008	CM-2
T1562.008	IA-2
T1562.008	IA-4
T1562.008	SI-4
T1562.001	CM-6
T1562.001	AC-2
T1562.001	AC-3
T1562.001	AC-5
T1562.001	AC-6
T1562.001	CA-7
T1562.001	SI-3
T1562.001	SI-7
T1562.001	CM-5
T1562.001	CM-7
T1562.007	AC-2
T1562.007	AC-3
T1562.007	AC-5
T1562.007	AC-6
T1562.007	CM-5
T1562.007	CM-7
T1562.008	AC-2
T1562.008	AC-3
T1562.008	AC-5
T1562.008	AC-6
T1562.008	CM-5
T1562.008	CM-7
T1566	SI-2
T1566	SI-3
T1566	SI-4
T1566	SI-8
T1566	CA-7
T1566	SC-7
T1566	SC-44
T1566	AC-4
T1566	CM-2
T1566	CM-6
T1566	IA-9
T1566	SC-20
T1580	AC-2
T1580	AC-3
T1580	AC-5
T1580	AC-6
T1580	IA-2
T1648	CA-7
T1648	SI-3
T1648	AC-6
T1648	AC-5
\.


                                                                                                                                                                                                                                                                                                                                                                                                                                                          4455.dat                                                                                            0000600 0004000 0002000 00000115334 14362250176 0014270 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        T1040	8.2.1
T1040	10.6
T1040	8.6
T1040	8.5
T1040	8.3
T1040	8.2.2
T1040	8.2
T1040	8.1
T1040	7.1.4
T1040	2.1
T1040	12.3
T1040	9.3
T1040	8.7
T1040	7.2
T1040	7.1
T1040	6.4.2
T1040	8.5.1
T1040	8.1.5
T1040	2.3
T1040	12.3.9
T1040	12.3.8
T1040	12.3.10
T1040	2
T1040	1
T1040	11.5.1
T1040	6.1
T1040	12.2
T1040	12.10.6
T1040	12.10.5
T1040	12.10.1
T1040	12.1
T1040	11.5
T1040	11.4
T1040	11.3
T1040	11.2
T1040	11.1
T1040	10.9
T1040	10.6.2
T1040	10.6.1
T1040	10.1
T1040	1.1.3
T1040	1.1.2
T1040	1.1.1
T1040	5
T1040	12.5.2
T1040	10.6.3
T1040	9.9.2
T1040	6.7
T1040	6.6
T1040	6.5
T1040	6.4
T1040	6.3
T1046	6.2
T1046	2.2
T1046	11.4
T1046	11.3
T1046	10.8
T1046	10.6.2
T1046	10.6.1
T1046	10.6
T1046	1.3
T1046	1.2
T1046	1.1
T1046	2
T1046	1
T1046	1.1.3
T1046	1.1.2
T1046	1.1.1
T1046	9.3
T1046	7.2
T1046	7.1
T1046	6.4.2
T1046	6.4.1
T1046	11.5.1
T1046	9.9.3
T1046	9.1.1
T1046	8.1.5
T1046	6.1
T1046	12.5.2
T1046	12.2
T1046	12.11
T1046	12.10.6
T1046	12.10.5
T1046	12.10.1
T1046	12.1
T1046	11.5
T1046	11.2
T1046	11.1
T1046	10.9
T1046	10.6.3
T1046	10.1
T1046	12.10.5 
T1046	5
T1046	9.9
T1046	9.8
T1046	9.7
T1046	9.6
T1046	9.5
T1046	2.4
T1046	6.5
T1078	6.7
T1078	6.6
T1078	6.5
T1078	6.4
T1078	6.3
T1078	8.1.5
T1078	10.6
T1078	9.9.2
T1078	2.2
T1078	1.2
T1078	6.1
T1078	12.9
T1078	12.8
T1078	12.2
T1078	11.3
T1078	11.2
T1078	12.8.2
T1078	11.5.1
T1078	6.2
T1078	12.5.2
T1078	12.10.6
T1078	12.1
T1078	10.6.3
T1078	8.2.1
T1078	8.6
T1078	8.5
T1078	8.3
T1078	8.2.2
T1078	8.2
T1078	8.1
T1078	7.1.4
T1078	2.1
T1078	12.3
T1078.001	6.7
T1078.001	6.6
T1078.001	6.5
T1078.001	6.4
T1078.001	6.3
T1078.001	8.1.5
T1078.001	10.6
T1078.001	9.9.2
T1078.001	2.2
T1078.001	1.2
T1078.001	6.1
T1078.001	12.9
T1078.001	12.8
T1078.001	12.2
T1078.001	11.3
T1078.001	11.2
T1078.001	12.8.2
T1078.001	8.2.1
T1078.001	9.3
T1078.001	9.1.1
T1078.001	8.7
T1078.001	8.6
T1078.001	8.5
T1078.001	8.2.2
T1078.001	8.2
T1078.001	8.1
T1078.001	7.2
T1078.001	7.1.4
T1078.001	7.1
T1078.001	6.4.2
T1078.001	2.1
T1078.001	12.3
T1078.001	11.4
T1078.001	10.6.2
T1078.001	10.6.1
T1078.001	11.5.1
T1078.001	9.9.3
T1078.001	6.2
T1078.001	12.5.2
T1078.001	12.11
T1078.001	12.10.6
T1078.001	12.10.5
T1078.001	12.10.1
T1078.001	12.1
T1078.001	11.5
T1078.001	11.1
T1078.001	10.9
T1078.001	10.8
T1078.001	10.6.3
T1078.001	10.1
T1078.001	12.10.5 
T1078.004	6.7
T1078.004	6.6
T1078.004	6.5
T1078.004	6.4
T1078.004	6.3
T1078.004	8.1.5
T1078.004	10.6
T1078.004	9.9.2
T1078.004	2.2
T1078.004	1.2
T1078.004	6.1
T1078.004	12.9
T1078.004	12.8
T1078.004	12.2
T1078.004	11.3
T1078.004	11.2
T1078.004	12.8.2
T1078.004	8.2.1
T1078.004	9.3
T1078.004	9.1.1
T1078.004	8.7
T1078.004	8.6
T1078.004	8.5
T1078.004	8.2.2
T1078.004	8.2
T1078.004	8.1
T1078.004	7.2
T1078.004	7.1.4
T1078.004	7.1
T1078.004	6.4.2
T1078.004	2.1
T1078.004	12.3
T1078.004	11.4
T1078.004	10.6.2
T1078.004	10.6.1
T1078.004	11.5.1
T1078.004	9.9.3
T1078.004	6.2
T1078.004	12.5.2
T1078.004	12.11
T1078.004	12.10.6
T1078.004	12.10.5
T1078.004	12.10.1
T1078.004	12.1
T1078.004	11.5
T1078.004	11.1
T1078.004	10.9
T1078.004	10.8
T1078.004	10.6.3
T1078.004	10.1
T1078.004	12.10.5 
T1078.001	1.1.3
T1078.001	1.1.2
T1078.001	1.1.1
T1078.001	5
T1078.004	1.1.3
T1078.004	1.1.2
T1078.004	1.1.1
T1078.004	5
T1078.004	8.3
T1078.004	8.5.1
T1078.004	2.4
T1078.004	2.3
T1078.004	12.3.9
T1078.004	12.3.8
T1078.004	12.3.10
T1087.004	9.3
T1087.004	9.1.1
T1087.004	8.7
T1087.004	8.6
T1087.004	8.5
T1087.004	8.2.2
T1087.004	8.2
T1087.004	8.1
T1087.004	7.2
T1087.004	7.1.4
T1087.004	7.1
T1087.004	6.4.2
T1087.004	2.1
T1087.004	12.3
T1087.004	11.4
T1087.004	10.6.2
T1087.004	10.6.1
T1087.004	2.2
T1087.004	10.6
T1087.004	8.3
T1098	2.2
T1098	1.2
T1098	9.3
T1098	7.2
T1098	7.1
T1098	11.5.1
T1098	8.1.5
T1098	6.1
T1098	12.2
T1098	12.10.6
T1098	12.10.5
T1098	12.10.1
T1098	12.1
T1098	11.5
T1098	11.4
T1098	11.3
T1098	11.2
T1098	11.1
T1098	10.9
T1098	10.6.2
T1098	10.6.1
T1098	10.6
T1098	10.1
T1098	1.1.3
T1098	1.1.2
T1098	1.1.1
T1098	5
T1098	12.5.2
T1098	10.6.3
T1098.001	8.6
T1098.001	8.5
T1098.001	8.3
T1098.001	8.2.2
T1098.001	8.2
T1098.001	8.1
T1098.001	7.1.4
T1098.001	2.1
T1098.001	12.3
T1098.001	11.5.1
T1098.001	8.1.5
T1098.001	6.1
T1098.001	12.2
T1098.001	12.10.6
T1098.001	12.10.5
T1098.001	12.10.1
T1098.001	12.1
T1098.001	11.5
T1098.001	11.4
T1098.001	11.3
T1098.001	11.2
T1098.001	11.1
T1098.001	10.9
T1098.001	10.6.2
T1098.001	10.6.1
T1098.001	10.6
T1098.001	10.1
T1098.001	1.1.3
T1098.001	1.1.2
T1098.001	1.1.1
T1098.001	5
T1098.001	12.5.2
T1098.001	10.6.3
T1098.001	9.9.2
T1098.001	6.2
T1098.001	2.2
T1098.001	10.8
T1098.001	1.3
T1098.001	1.2
T1098.001	1.1
T1098.001	2
T1098.001	1
T1098.001	9.3
T1098.001	7.2
T1098.001	7.1
T1098.001	9.1.1
T1098.001	8.7
T1098.001	6.4.2
T1098.001	8.5.1
T1098.001	2.4
T1098.001	2.3
T1098.001	12.3.9
T1098.001	12.3.8
T1098.001	12.3.10
T1098.004	6.4.2
T1098.004	6.4.1
T1098.004	2.2
T1098.004	1.2
T1098.004	1.1.3
T1098.004	1.1.2
T1098.004	1.1.1
T1098.004	9.9
T1098.004	9.8
T1098.004	9.7
T1098.004	9.6
T1098.004	9.5
T1098.004	2.4
T1098.004	12.10.5
T1098.004	11.5
T1098.004	11.4
T1098.004	11.1
T1098.004	10.6.1
T1098.004	10.1
T1098.004	8.2.1
T1098.004	9.3
T1098.004	8.7
T1098.004	8.2.2
T1098.004	8.1
T1098.004	7.2
T1098.004	7.1.4
T1098.004	7.1
T1098.004	11.5.1
T1098.004	6.5
T1098.004	6.2
T1098.004	6.1
T1098.004	12.5.2
T1098.004	12.2
T1098.004	12.10.6
T1098.004	12.1
T1098.004	11.3
T1098.004	11.2
T1098.004	10.6.3
T1098.004	10.9
T1098.004	5
T1098.004	8.1.5
T1098.004	12.10.1
T1098.004	10.6.2
T1098.004	10.6
T1110.001	8.6
T1110.001	8.5
T1110.001	8.3
T1110.001	8.2.2
T1110.001	8.2
T1110.001	8.1
T1110.001	7.1.4
T1110.001	2.1
T1110.001	12.3
T1110.001	9.3
T1110.001	9.1.1
T1110.001	8.7
T1110.001	7.2
T1110.001	7.1
T1110.001	6.4.2
T1110.001	11.4
T1110.001	10.6.2
T1110.001	10.6.1
T1110.001	2.2
T1110.001	10.6
T1110.001	8.5.1
T1110.001	8.1.5
T1110.001	2.4
T1110.001	2.3
T1110.001	12.3.9
T1110.001	12.3.8
T1110.001	12.3.10
T1110.001	1.1.3
T1110.001	1.1.2
T1110.001	1.1.1
T1110.001	11.5.1
T1110.001	9.9.3
T1110.001	6.2
T1110.001	6.1
T1110.001	12.5.2
T1110.001	12.2
T1110.001	12.11
T1110.001	12.10.6
T1110.001	12.10.5
T1110.001	12.10.1
T1110.001	12.1
T1110.001	11.5
T1110.001	11.3
T1110.001	11.2
T1110.001	11.1
T1110.001	10.9
T1110.001	10.8
T1110.001	10.6.3
T1110.001	10.1
T1110.001	12.10.5 
T1110.001	5
T1110.001	6.4.1
T1110.001	1.2
T1110.002	8.6
T1110.002	8.5
T1110.002	8.3
T1110.002	8.2.2
T1110.002	8.2
T1110.002	8.1
T1110.002	7.1.4
T1110.002	2.1
T1110.002	12.3
T1110.002	9.3
T1110.002	9.1.1
T1110.002	8.7
T1110.002	7.2
T1110.002	7.1
T1110.002	6.4.2
T1110.002	11.4
T1110.002	10.6.2
T1110.002	10.6.1
T1110.002	2.2
T1110.002	10.6
T1110.002	8.5.1
T1110.002	8.1.5
T1110.002	2.4
T1110.002	2.3
T1110.002	12.3.9
T1110.002	12.3.8
T1110.002	12.3.10
T1110.002	1.1.3
T1110.002	1.1.2
T1110.002	1.1.1
T1110.002	11.5.1
T1110.002	9.9.3
T1110.002	6.2
T1110.002	6.1
T1110.002	12.5.2
T1110.002	12.2
T1110.002	12.11
T1110.002	12.10.6
T1110.002	12.10.5
T1110.002	12.10.1
T1110.002	12.1
T1110.002	11.5
T1110.002	11.3
T1110.002	11.2
T1110.002	11.1
T1110.002	10.9
T1110.002	10.8
T1110.002	10.6.3
T1110.002	10.1
T1110.002	12.10.5 
T1110.002	5
T1110.002	6.4.1
T1110.002	1.2
T1110.003	8.6
T1110.003	8.5
T1110.003	8.3
T1110.003	8.2.2
T1110.003	8.2
T1110.003	8.1
T1110.003	7.1.4
T1110.003	2.1
T1110.003	12.3
T1110.003	9.3
T1110.003	9.1.1
T1110.003	8.7
T1110.003	7.2
T1110.003	7.1
T1110.003	6.4.2
T1110.003	11.4
T1110.003	10.6.2
T1110.003	10.6.1
T1110.003	2.2
T1110.003	10.6
T1110.003	8.5.1
T1110.003	8.1.5
T1110.003	2.4
T1110.003	2.3
T1110.003	12.3.9
T1110.003	12.3.8
T1110.003	12.3.10
T1110.003	1.1.3
T1110.003	1.1.2
T1110.003	1.1.1
T1110.003	11.5.1
T1110.003	9.9.3
T1110.003	6.2
T1110.003	6.1
T1110.003	12.5.2
T1110.003	12.2
T1110.003	12.11
T1110.003	12.10.6
T1110.003	12.10.5
T1110.003	12.10.1
T1110.003	12.1
T1110.003	11.5
T1110.003	11.3
T1110.003	11.2
T1110.003	11.1
T1110.003	10.9
T1110.003	10.8
T1110.003	10.6.3
T1110.003	10.1
T1110.003	12.10.5 
T1110.003	5
T1110.003	6.4.1
T1110.003	1.2
T1110.004	8.6
T1110.004	8.5
T1110.004	8.3
T1110.004	8.2.2
T1110.004	8.2
T1110.004	8.1
T1110.004	7.1.4
T1110.004	2.1
T1110.004	12.3
T1110.004	9.3
T1110.004	9.1.1
T1110.004	8.7
T1110.004	7.2
T1110.004	7.1
T1110.004	6.4.2
T1110.004	11.4
T1110.004	10.6.2
T1110.004	10.6.1
T1110.004	2.2
T1110.004	10.6
T1110.004	8.5.1
T1110.004	8.1.5
T1110.004	2.4
T1110.004	2.3
T1110.004	12.3.9
T1110.004	12.3.8
T1110.004	12.3.10
T1110.004	1.1.3
T1110.004	1.1.2
T1110.004	1.1.1
T1110.004	11.5.1
T1110.004	9.9.3
T1110.004	6.2
T1110.004	6.1
T1110.004	12.5.2
T1110.004	12.2
T1110.004	12.11
T1110.004	12.10.6
T1110.004	12.10.5
T1110.004	12.10.1
T1110.004	12.1
T1110.004	11.5
T1110.004	11.3
T1110.004	11.2
T1110.004	11.1
T1110.004	10.9
T1110.004	10.8
T1110.004	10.6.3
T1110.004	10.1
T1110.004	12.10.5 
T1110.004	5
T1110.004	6.4.1
T1110.004	1.2
T1119	11.5.1
T1119	8.1.5
T1119	6.1
T1119	12.2
T1119	12.10.6
T1119	12.10.5
T1119	12.10.1
T1119	12.1
T1119	11.5
T1119	11.4
T1119	11.3
T1119	11.2
T1119	11.1
T1119	10.9
T1119	10.6.2
T1119	10.6.1
T1119	10.6
T1119	10.1
T1119	1.1.3
T1119	1.1.2
T1119	1.1.1
T1119	5
T1119	12.5.2
T1119	10.6.3
T1119	9.9.2
T1119	6.7
T1119	6.6
T1119	6.5
T1119	6.4
T1119	6.3
T1119	9.5.1
T1119	12.10.2
T1119	12.5.3
T1119	11.1.2
T1119	2
T1119	1
T1119	6.4.2
T1119	6.4.1
T1119	2.2
T1119	1.2
T1119	9.9
T1119	9.8
T1119	9.7
T1119	9.6
T1119	9.5
T1119	2.4
T1119	9.3
T1119	8.7
T1119	8.2.2
T1119	8.1
T1119	7.2
T1119	7.1.4
T1119	7.1
T1119	8.5.1
T1119	8.3
T1119	2.3
T1119	12.3.9
T1119	12.3.8
T1119	12.3.10
T1136.003	9.3
T1136.003	9.1.1
T1136.003	8.7
T1136.003	8.6
T1136.003	8.5
T1136.003	8.2.2
T1136.003	8.2
T1136.003	8.1
T1136.003	7.2
T1136.003	7.1.4
T1136.003	7.1
T1136.003	6.4.2
T1136.003	2.1
T1136.003	12.3
T1136.003	11.4
T1136.003	10.6.2
T1136.003	10.6.1
T1136.003	2.2
T1136.003	10.6
T1136.003	8.5.1
T1136.003	8.3
T1136.003	8.1.5
T1136.003	2.4
T1136.003	2.3
T1136.003	12.3.9
T1136.003	12.3.8
T1136.003	12.3.10
T1136.003	1.1.3
T1136.003	1.1.2
T1136.003	1.1.1
T1136.003	11.5.1
T1136.003	6.1
T1136.003	12.2
T1136.003	12.10.6
T1136.003	12.10.5
T1136.003	12.10.1
T1136.003	12.1
T1136.003	11.5
T1136.003	11.3
T1136.003	11.2
T1136.003	11.1
T1136.003	10.9
T1136.003	10.1
T1136.003	5
T1136.003	12.5.2
T1136.003	10.6.3
T1136.003	9.9.2
T1136.003	1.2
T1136.003	6.2
T1136.003	10.8
T1136.003	1.3
T1136.003	1.1
T1136.003	2
T1136.003	1
T1189	6.4.2
T1189	6.4.1
T1189	2.2
T1189	1.2
T1189	1.1.3
T1189	1.1.2
T1189	1.1.1
T1189	6.2
T1189	11.3
T1189	10.8
T1189	10.6
T1189	1.3
T1189	1.1
T1189	2
T1189	1
T1189	9.3
T1189	8.7
T1189	7.2
T1189	7.1
T1189	11.4
T1189	10.6.2
T1189	10.6.1
T1189	5
T1189	9.9
T1189	9.8
T1189	9.7
T1189	9.6
T1189	9.5
T1189	2.4
T1189	12.10.5
T1189	11.5
T1189	11.1
T1189	10.1
T1189	12.1
T1189	11.2
T1189	10.9
T1189	11.5.1
T1189	8.1.5
T1189	6.1
T1189	12.2
T1189	12.10.6
T1189	12.10.1
T1189	12.5.2
T1189	10.6.3
T1189	9.9.3
T1189	9.1.1
T1189	12.11
T1189	12.10.5 
T1189	9.9.2
T1189	6.5
T1190	11.5.1
T1190	6.5
T1190	6.2
T1190	6.1
T1190	12.5.2
T1190	12.2
T1190	12.10.6
T1190	12.1
T1190	11.3
T1190	11.2
T1190	10.6.3
T1190	9.9.3
T1190	12.11
T1190	12.10.1
T1190	11.4
T1190	10.9
T1190	10.8
T1190	10.6.1
T1190	9.1.1
T1190	8.1.5
T1190	12.10.5
T1190	11.5
T1190	11.1
T1190	10.6.2
T1190	10.6
T1190	10.1
T1190	12.10.5 
T1190	9.3
T1190	8.7
T1190	8.6
T1190	8.5
T1190	8.2.2
T1190	8.2
T1190	8.1
T1190	7.2
T1190	7.1.4
T1190	7.1
T1190	6.4.2
T1190	2.1
T1190	12.3
T1190	2.2
T1190	1.3
T1190	1.2
T1190	1.1.3
T1190	1.1.2
T1190	1.1.1
T1190	1.1
T1190	2
T1190	1
T1190	8.3
T1190	5
T1190	9.9
T1190	9.8
T1190	9.7
T1190	9.6
T1190	9.5
T1190	2.4
T1190	6.7
T1190	6.6
T1190	6.4
T1190	6.3
T1190	9.9.2
T1199	6.2
T1199	2.2
T1199	11.4
T1199	11.3
T1199	10.8
T1199	10.6.2
T1199	10.6.1
T1199	10.6
T1199	1.3
T1199	1.2
T1199	1.1
T1199	2
T1199	1
T1199	1.1.3
T1199	1.1.2
T1199	1.1.1
T1199	9.3
T1199	7.2
T1199	7.1
T1199	8.7
T1199	8.2.2
T1199	8.1
T1199	7.1.4
T1199	6.4.2
T1199	8.3
T1199	8.2
T1201	11.5.1
T1201	9.9.3
T1201	9.1.1
T1201	8.1.5
T1201	6.2
T1201	6.1
T1201	12.5.2
T1201	12.2
T1201	12.11
T1201	12.10.6
T1201	12.10.5
T1201	12.10.1
T1201	12.1
T1201	11.5
T1201	11.4
T1201	11.3
T1201	11.2
T1201	11.1
T1201	10.9
T1201	10.8
T1201	10.6.3
T1201	10.6.2
T1201	10.6.1
T1201	10.6
T1201	10.1
T1201	12.10.5 
T1201	6.4.2
T1201	6.4.1
T1201	2.2
T1201	1.2
T1201	1.1.3
T1201	1.1.2
T1201	1.1.1
T1201	5
T1204.003	12.1
T1204.003	11.3
T1204.003	11.2
T1204.003	10.9
T1204.003	10.6.1
T1204.003	5
T1204.003	11.5.1
T1204.003	8.1.5
T1204.003	6.1
T1204.003	12.2
T1204.003	12.10.6
T1204.003	12.10.5
T1204.003	12.10.1
T1204.003	11.5
T1204.003	11.4
T1204.003	11.1
T1204.003	10.6.2
T1204.003	10.6
T1204.003	10.1
T1204.003	1.1.3
T1204.003	1.1.2
T1204.003	1.1.1
T1204.003	12.5.2
T1204.003	10.6.3
T1204.003	9.9.3
T1204.003	9.1.1
T1204.003	6.2
T1204.003	12.11
T1204.003	10.8
T1204.003	12.10.5 
T1204.003	2.2
T1204.003	1.3
T1204.003	1.2
T1204.003	1.1
T1204.003	2
T1204.003	1
T1204.003	6.4.2
T1204.003	6.4.1
T1204.003	9.3
T1204.003	7.2
T1204.003	7.1
T1204.003	6.5
T1204.003	9.9.2
T1485	9.3
T1485	8.7
T1485	8.2.2
T1485	8.1
T1485	7.2
T1485	7.1.4
T1485	7.1
T1485	6.4.2
T1485	2.2
T1485	10.6
T1485	6.4.1
T1485	1.2
T1485	1.1.3
T1485	1.1.2
T1485	1.1.1
T1485	11.5.1
T1485	9.6.1
T1485	12.9
T1485	12.8
T1485	12.5.3
T1485	12.5.2
T1485	12.5
T1485	12.4
T1485	12.2
T1485	12.11
T1485	12.10.6
T1485	12.10.1
T1485	12.1
T1485	11.1.2
T1485	10.8
T1485	10.6.3
T1485	9.5.1
T1485	12.10.2
T1485	11.3
T1485	11.2
T1485	10.9
T1485	10.6.1
T1485	5
T1485	8.1.5
T1485	6.1
T1485	12.10.5
T1485	11.5
T1485	11.4
T1485	11.1
T1485	10.6.2
T1485	10.1
T1485	9.9.2
T1486	9.3
T1486	8.7
T1486	8.2.2
T1486	8.1
T1486	7.2
T1486	7.1.4
T1486	7.1
T1486	6.4.2
T1486	2.2
T1486	10.6
T1486	6.4.1
T1486	1.2
T1486	1.1.3
T1486	1.1.2
T1486	1.1.1
T1486	11.5.1
T1486	9.6.1
T1486	12.9
T1486	12.8
T1486	12.5.3
T1486	12.5.2
T1486	12.5
T1486	12.4
T1486	12.2
T1486	12.11
T1486	12.10.6
T1486	12.10.1
T1486	12.1
T1486	11.1.2
T1486	10.8
T1486	10.6.3
T1486	9.5.1
T1486	12.10.2
T1486	11.3
T1486	11.2
T1486	10.9
T1486	10.6.1
T1486	5
T1486	8.1.5
T1486	6.1
T1486	12.10.5
T1486	11.5
T1486	11.4
T1486	11.1
T1486	10.6.2
T1486	10.1
T1486	9.9.2
T1491.002	9.3
T1491.002	8.7
T1491.002	8.2.2
T1491.002	8.1
T1491.002	7.2
T1491.002	7.1.4
T1491.002	7.1
T1491.002	6.4.2
T1491.002	2.2
T1491.002	10.6
T1491.002	6.4.1
T1491.002	1.2
T1491.002	1.1.3
T1491.002	1.1.2
T1491.002	1.1.1
T1491.002	11.5.1
T1491.002	9.6.1
T1491.002	12.9
T1491.002	12.8
T1491.002	12.5.3
T1491.002	12.5.2
T1491.002	12.5
T1491.002	12.4
T1491.002	12.2
T1491.002	12.11
T1491.002	12.10.6
T1491.002	12.10.1
T1491.002	12.1
T1491.002	11.1.2
T1491.002	10.8
T1491.002	10.6.3
T1491.002	9.5.1
T1491.002	12.10.2
T1491.002	11.3
T1491.002	11.2
T1491.002	10.9
T1491.002	10.6.1
T1491.002	5
T1491.002	8.1.5
T1491.002	6.1
T1491.002	12.10.5
T1491.002	11.5
T1491.002	11.4
T1491.002	11.1
T1491.002	10.6.2
T1491.002	10.1
T1491.002	9.9.2
T1498.001	9.3
T1498.001	8.7
T1498.001	8.2.2
T1498.001	8.1
T1498.001	7.2
T1498.001	7.1.4
T1498.001	7.1
T1498.001	6.4.2
T1498.001	2.2
T1498.001	6.2
T1498.001	11.3
T1498.001	10.8
T1498.001	10.6
T1498.001	1.3
T1498.001	1.2
T1498.001	1.1.3
T1498.001	1.1.2
T1498.001	1.1.1
T1498.001	1.1
T1498.001	2
T1498.001	1
T1498.001	11.5.1
T1498.001	9.9.3
T1498.001	9.1.1
T1498.001	8.1.5
T1498.001	6.1
T1498.001	12.5.2
T1498.001	12.2
T1498.001	12.11
T1498.001	12.10.6
T1498.001	12.10.5
T1498.001	12.10.1
T1498.001	12.1
T1498.001	11.5
T1498.001	11.4
T1498.001	11.2
T1498.001	11.1
T1498.001	10.9
T1498.001	10.6.3
T1498.001	10.6.2
T1498.001	10.6.1
T1498.001	10.1
T1498.001	12.10.5 
T1498.002	9.3
T1498.002	8.7
T1498.002	8.2.2
T1498.002	8.1
T1498.002	7.2
T1498.002	7.1.4
T1498.002	7.1
T1498.002	6.4.2
T1498.002	2.2
T1498.002	6.2
T1498.002	11.3
T1498.002	10.8
T1498.002	10.6
T1498.002	1.3
T1498.002	1.2
T1498.002	1.1.3
T1498.002	1.1.2
T1498.002	1.1.1
T1498.002	1.1
T1498.002	2
T1498.002	1
T1498.002	11.5.1
T1498.002	9.9.3
T1498.002	9.1.1
T1498.002	8.1.5
T1498.002	6.1
T1498.002	12.5.2
T1498.002	12.2
T1498.002	12.11
T1498.002	12.10.6
T1498.002	12.10.5
T1498.002	12.10.1
T1498.002	12.1
T1498.002	11.5
T1498.002	11.4
T1498.002	11.2
T1498.002	11.1
T1498.002	10.9
T1498.002	10.6.3
T1498.002	10.6.2
T1498.002	10.6.1
T1498.002	10.1
T1498.002	12.10.5 
T1499.002	9.3
T1499.002	8.7
T1499.002	8.2.2
T1499.002	8.1
T1499.002	7.2
T1499.002	7.1.4
T1499.002	7.1
T1499.002	6.4.2
T1499.002	2.2
T1499.002	6.2
T1499.002	11.3
T1499.002	10.8
T1499.002	10.6
T1499.002	1.3
T1499.002	1.2
T1499.002	1.1.3
T1499.002	1.1.2
T1499.002	1.1.1
T1499.002	1.1
T1499.002	2
T1499.002	1
T1499.002	11.5.1
T1499.002	9.9.3
T1499.002	9.1.1
T1499.002	8.1.5
T1499.002	6.1
T1499.002	12.5.2
T1499.002	12.2
T1499.002	12.11
T1499.002	12.10.6
T1499.002	12.10.5
T1499.002	12.10.1
T1499.002	12.1
T1499.002	11.5
T1499.002	11.4
T1499.002	11.2
T1499.002	11.1
T1499.002	10.9
T1499.002	10.6.3
T1499.002	10.6.2
T1499.002	10.6.1
T1499.002	10.1
T1499.002	12.10.5 
T1499.002	5
T1499.003	9.3
T1499.003	8.7
T1499.003	8.2.2
T1499.003	8.1
T1499.003	7.2
T1499.003	7.1.4
T1499.003	7.1
T1499.003	6.4.2
T1499.003	2.2
T1499.003	6.2
T1499.003	11.3
T1499.003	10.8
T1499.003	10.6
T1499.003	1.3
T1499.003	1.2
T1499.003	1.1.3
T1499.003	1.1.2
T1499.003	1.1.1
T1499.003	1.1
T1499.003	2
T1499.003	1
T1499.003	11.5.1
T1499.003	9.9.3
T1499.003	9.1.1
T1499.003	8.1.5
T1499.003	6.1
T1499.003	12.5.2
T1499.003	12.2
T1499.003	12.11
T1499.003	12.10.6
T1499.003	12.10.5
T1499.003	12.10.1
T1499.003	12.1
T1499.003	11.5
T1499.003	11.4
T1499.003	11.2
T1499.003	11.1
T1499.003	10.9
T1499.003	10.6.3
T1499.003	10.6.2
T1499.003	10.6.1
T1499.003	10.1
T1499.003	12.10.5 
T1499.003	5
T1499.004	9.3
T1499.004	8.7
T1499.004	8.2.2
T1499.004	8.1
T1499.004	7.2
T1499.004	7.1.4
T1499.004	7.1
T1499.004	6.4.2
T1499.004	2.2
T1499.004	6.2
T1499.004	11.3
T1499.004	10.8
T1499.004	10.6
T1499.004	1.3
T1499.004	1.2
T1499.004	1.1.3
T1499.004	1.1.2
T1499.004	1.1.1
T1499.004	1.1
T1499.004	2
T1499.004	1
T1499.004	11.5.1
T1499.004	9.9.3
T1499.004	9.1.1
T1499.004	8.1.5
T1499.004	6.1
T1499.004	12.5.2
T1499.004	12.2
T1499.004	12.11
T1499.004	12.10.6
T1499.004	12.10.5
T1499.004	12.10.1
T1499.004	12.1
T1499.004	11.5
T1499.004	11.4
T1499.004	11.2
T1499.004	11.1
T1499.004	10.9
T1499.004	10.6.3
T1499.004	10.6.2
T1499.004	10.6.1
T1499.004	10.1
T1499.004	12.10.5 
T1499.004	5
T1525	11.5.1
T1525	8.1.5
T1525	6.1
T1525	12.2
T1525	12.10.6
T1525	12.10.5
T1525	12.10.1
T1525	12.1
T1525	11.5
T1525	11.4
T1525	11.3
T1525	11.2
T1525	11.1
T1525	10.9
T1525	10.6.2
T1525	10.6.1
T1525	10.6
T1525	10.1
T1525	1.1.3
T1525	1.1.2
T1525	1.1.1
T1525	5
T1525	12.5.2
T1525	10.6.3
T1525	9.3
T1525	9.1.1
T1525	8.7
T1525	8.6
T1525	8.5
T1525	8.2.2
T1525	8.2
T1525	8.1
T1525	7.2
T1525	7.1.4
T1525	7.1
T1525	6.4.2
T1525	2.1
T1525	12.3
T1525	2.2
T1525	1.2
T1525	8.3
T1525	9.9.2
T1525	6.5
T1525	6.2
T1525	6.4.1
T1528	9.3
T1528	9.1.1
T1528	8.7
T1528	8.6
T1528	8.5
T1528	8.2.2
T1528	8.2
T1528	8.1
T1528	7.2
T1528	7.1.4
T1528	7.1
T1528	6.4.2
T1528	2.1
T1528	12.3
T1528	11.4
T1528	10.6.2
T1528	10.6.1
T1528	2.2
T1528	6.2
T1528	11.3
T1528	10.8
T1528	10.6
T1528	1.3
T1528	1.2
T1528	1.1.3
T1528	1.1.2
T1528	1.1.1
T1528	1.1
T1528	2
T1528	1
T1528	6.4.1
T1528	11.5.1
T1528	9.9.3
T1528	8.1.5
T1528	6.1
T1528	12.5.2
T1528	12.2
T1528	12.11
T1528	12.10.6
T1528	12.10.5
T1528	12.10.1
T1528	12.1
T1528	11.5
T1528	11.2
T1528	11.1
T1528	10.9
T1528	10.6.3
T1528	10.1
T1528	12.10.5 
T1528	5
T1528	8.3
T1528	6.5
T1528	6.7
T1528	6.6
T1528	6.4
T1528	6.3
T1528	12.8
T1528	12.9
T1530	9.3
T1530	9.1.1
T1530	8.7
T1530	8.6
T1530	8.5
T1530	8.2.2
T1530	8.2
T1530	8.1
T1530	7.2
T1530	7.1.4
T1530	7.1
T1530	6.4.2
T1530	2.1
T1530	12.3
T1530	11.4
T1530	10.6.2
T1530	10.6.1
T1530	2.2
T1530	10.6
T1530	8.5.1
T1530	8.3
T1530	8.1.5
T1530	2.4
T1530	2.3
T1530	12.3.9
T1530	12.3.8
T1530	12.3.10
T1530	1.1.3
T1530	1.1.2
T1530	1.1.1
T1530	6.2
T1530	11.3
T1530	10.8
T1530	1.3
T1530	1.2
T1530	1.1
T1530	2
T1530	1
T1530	6.4.1
T1530	9.9
T1530	9.8
T1530	9.7
T1530	9.6
T1530	9.5
T1530	12.10.5
T1530	11.5
T1530	11.1
T1530	10.1
T1530	11.5.1
T1530	9.9.3
T1530	6.1
T1530	12.5.2
T1530	12.2
T1530	12.11
T1530	12.10.6
T1530	12.10.1
T1530	12.1
T1530	11.2
T1530	10.9
T1530	10.6.3
T1530	12.10.5 
T1530	8.2.1
T1530	5
T1530	9.9.2
T1530	6.7
T1530	6.6
T1530	6.5
T1530	6.4
T1530	6.3
T1537	9.3
T1537	9.1.1
T1537	8.7
T1537	8.6
T1537	8.5
T1537	8.2.2
T1537	8.2
T1537	8.1
T1537	7.2
T1537	7.1.4
T1537	7.1
T1537	6.4.2
T1537	2.1
T1537	12.3
T1537	11.4
T1537	10.6.2
T1537	10.6.1
T1537	2.2
T1537	6.2
T1537	11.3
T1537	10.8
T1537	10.6
T1537	1.3
T1537	1.2
T1537	1.1.3
T1537	1.1.2
T1537	1.1.1
T1537	1.1
T1537	2
T1537	1
T1537	8.5.1
T1537	8.3
T1537	8.1.5
T1537	2.3
T1537	12.3.9
T1537	12.3.8
T1537	12.3.10
T1537	2.4
T1537	11.5.1
T1537	9.9.3
T1537	6.1
T1537	12.5.2
T1537	12.2
T1537	12.11
T1537	12.10.6
T1537	12.10.5
T1537	12.10.1
T1537	12.1
T1537	11.5
T1537	11.2
T1537	11.1
T1537	10.9
T1537	10.6.3
T1537	10.1
T1537	12.10.5 
T1537	5
T1538	9.3
T1538	9.1.1
T1538	8.7
T1538	8.6
T1538	8.5
T1538	8.2.2
T1538	8.2
T1538	8.1
T1538	7.2
T1538	7.1.4
T1538	7.1
T1538	6.4.2
T1538	2.1
T1538	12.3
T1538	11.4
T1538	10.6.2
T1538	10.6.1
T1538	2.2
T1538	10.6
T1538	8.3
T1550.001	8.2.1
T1550.001	10.6
T1550.001	6.4.2
T1550.001	6.4.1
T1550.001	2.2
T1550.001	1.2
T1550.001	1.1.3
T1550.001	1.1.2
T1550.001	1.1.1
T1550.001	9.1.1
T1550.001	9.3
T1550.001	8.7
T1550.001	8.2.2
T1550.001	8.1
T1550.001	7.2
T1550.001	7.1.4
T1550.001	7.1
T1550.001	8.5.1
T1550.001	8.3
T1550.001	8.1.5
T1550.001	2.3
T1550.001	12.3.9
T1550.001	12.3.8
T1550.001	12.3.10
T1550.001	2
T1550.001	1
T1550.001	2.4
T1550.001	11.5.1
T1550.001	6.1
T1550.001	12.2
T1550.001	12.10.6
T1550.001	12.10.5
T1550.001	12.10.1
T1550.001	12.1
T1550.001	11.5
T1550.001	11.4
T1550.001	11.3
T1550.001	11.2
T1550.001	11.1
T1550.001	10.9
T1550.001	10.6.2
T1550.001	10.6.1
T1550.001	10.1
T1550.001	5
T1550.001	12.5.2
T1550.001	10.6.3
T1550.001	9.9.2
T1550.001	6.7
T1550.001	6.6
T1550.001	6.5
T1550.001	6.4
T1550.001	6.3
T1550.001	8.6
T1550.001	8.5
T1550.001	8.2
T1550.001	2.1
T1550.001	12.3
T1552.001	6.4.2
T1552.001	6.4.1
T1552.001	2.2
T1552.001	1.2
T1552.001	1.1.3
T1552.001	1.1.2
T1552.001	1.1.1
T1552.001	8.6
T1552.001	8.5
T1552.001	8.3
T1552.001	8.2.2
T1552.001	8.2
T1552.001	8.1
T1552.001	7.1.4
T1552.001	2.1
T1552.001	12.3
T1552.001	9.3
T1552.001	8.7
T1552.001	7.2
T1552.001	7.1
T1552.001	10.6
T1552.001	9.1.1
T1552.001	11.4
T1552.001	10.6.2
T1552.001	10.6.1
T1552.001	6.2
T1552.001	11.3
T1552.001	10.8
T1552.001	1.3
T1552.001	1.1
T1552.001	2
T1552.001	1
T1552.001	11.5.1
T1552.001	9.9.3
T1552.001	8.1.5
T1552.001	6.1
T1552.001	12.5.2
T1552.001	12.2
T1552.001	12.11
T1552.001	12.10.6
T1552.001	12.10.5
T1552.001	12.10.1
T1552.001	12.1
T1552.001	11.5
T1552.001	11.2
T1552.001	11.1
T1552.001	10.9
T1552.001	10.6.3
T1552.001	10.1
T1552.001	12.10.5 
T1552.001	8.2.1
T1552.001	5
T1552.001	6.7
T1552.001	6.6
T1552.001	6.5
T1552.001	6.4
T1552.001	6.3
T1552.001	12.8
T1552.001	12.9
T1552.005	11.5.1
T1552.005	9.9.3
T1552.005	9.1.1
T1552.005	8.1.5
T1552.005	6.2
T1552.005	6.1
T1552.005	12.5.2
T1552.005	12.2
T1552.005	12.11
T1552.005	12.10.6
T1552.005	12.10.5
T1552.005	12.10.1
T1552.005	12.1
T1552.005	11.5
T1552.005	11.4
T1552.005	11.3
T1552.005	11.2
T1552.005	11.1
T1552.005	10.9
T1552.005	10.8
T1552.005	10.6.3
T1552.005	10.6.2
T1552.005	10.6.1
T1552.005	10.6
T1552.005	10.1
T1552.005	12.10.5 
T1552.005	2.2
T1552.005	1.2
T1552.005	9.3
T1552.005	7.2
T1552.005	7.1
T1552.005	8.6
T1552.005	8.5
T1552.005	8.3
T1552.005	8.2
T1552.005	8.1
T1552.005	2.1
T1552.005	12.3
T1552.005	8.2.2
T1552.005	7.1.4
T1552.005	1.3
T1552.005	1.1
T1552.005	2
T1552.005	1
T1552.005	1.1.3
T1552.005	1.1.2
T1552.005	1.1.1
T1552.005	5
T1552.005	8.7
T1552.005	6.4.2
T1552.005	8.5.1
T1552.005	2.4
T1552.005	2.3
T1552.005	12.3.9
T1552.005	12.3.8
T1552.005	12.3.10
T1562.001	6.1
T1562.001	12.2
T1562.001	11.3
T1562.001	11.2
T1562.001	11.5.1
T1562.001	6.5
T1562.001	6.2
T1562.001	12.5.2
T1562.001	12.10.6
T1562.001	12.1
T1562.001	10.6.3
T1562.001	6.4.2
T1562.001	6.4.1
T1562.001	2.2
T1562.001	1.2
T1562.001	1.1.3
T1562.001	1.1.2
T1562.001	1.1.1
T1562.001	8.6
T1562.001	8.5
T1562.001	8.3
T1562.001	8.2.2
T1562.001	8.2
T1562.001	8.1
T1562.001	7.1.4
T1562.001	2.1
T1562.001	12.3
T1562.001	8.1.5
T1562.001	12.10.5
T1562.001	12.10.1
T1562.001	11.5
T1562.001	11.4
T1562.001	11.1
T1562.001	10.9
T1562.001	10.6.2
T1562.001	10.6.1
T1562.001	10.6
T1562.001	10.1
T1562.001	5
T1562.007	6.1
T1562.007	12.2
T1562.007	11.3
T1562.007	11.2
T1562.007	11.5.1
T1562.007	6.5
T1562.007	6.2
T1562.007	12.5.2
T1562.007	12.10.6
T1562.007	12.1
T1562.007	10.6.3
T1562.007	6.4.2
T1562.007	6.4.1
T1562.007	2.2
T1562.007	1.2
T1562.007	1.1.3
T1562.007	1.1.2
T1562.007	1.1.1
T1562.007	8.6
T1562.007	8.5
T1562.007	8.3
T1562.007	8.2.2
T1562.007	8.2
T1562.007	8.1
T1562.007	7.1.4
T1562.007	2.1
T1562.007	12.3
T1562.007	8.1.5
T1562.007	12.10.5
T1562.007	12.10.1
T1562.007	11.5
T1562.007	11.4
T1562.007	11.1
T1562.007	10.9
T1562.007	10.6.2
T1562.007	10.6.1
T1562.007	10.6
T1562.007	10.1
T1562.007	5
T1562.008	6.1
T1562.008	12.2
T1562.008	11.3
T1562.008	11.2
T1562.008	11.5.1
T1562.008	6.5
T1562.008	6.2
T1562.008	12.5.2
T1562.008	12.10.6
T1562.008	12.1
T1562.008	10.6.3
T1562.008	6.4.2
T1562.008	6.4.1
T1562.008	2.2
T1562.008	1.2
T1562.008	1.1.3
T1562.008	1.1.2
T1562.008	1.1.1
T1562.008	8.6
T1562.008	8.5
T1562.008	8.3
T1562.008	8.2.2
T1562.008	8.2
T1562.008	8.1
T1562.008	7.1.4
T1562.008	2.1
T1562.008	12.3
T1562.008	8.1.5
T1562.008	12.10.5
T1562.008	12.10.1
T1562.008	11.5
T1562.008	11.4
T1562.008	11.1
T1562.008	10.9
T1562.008	10.6.2
T1562.008	10.6.1
T1562.008	10.6
T1562.008	10.1
T1562.008	5
T1562.001	9.3
T1562.001	9.1.1
T1562.001	8.7
T1562.001	7.2
T1562.001	7.1
T1562.001	9.9.3
T1562.001	12.11
T1562.001	10.8
T1562.001	12.10.5 
T1562.001	9.9.2
T1562.007	9.3
T1562.007	9.1.1
T1562.007	8.7
T1562.007	7.2
T1562.007	7.1
T1562.008	9.3
T1562.008	9.1.1
T1562.008	8.7
T1562.008	7.2
T1562.008	7.1
T1566	6.5
T1566	6.2
T1566	6.1
T1566	12.2
T1566	11.3
T1566	11.2
T1566	12.1
T1566	10.9
T1566	10.6.1
T1566	5
T1566	11.5.1
T1566	8.1.5
T1566	12.10.6
T1566	12.10.5
T1566	12.10.1
T1566	11.5
T1566	11.4
T1566	11.1
T1566	10.6.2
T1566	10.6
T1566	10.1
T1566	1.1.3
T1566	1.1.2
T1566	1.1.1
T1566	12.5.2
T1566	10.6.3
T1566	9.9.3
T1566	9.1.1
T1566	12.11
T1566	10.8
T1566	12.10.5 
T1566	2.2
T1566	1.3
T1566	1.2
T1566	1.1
T1566	2
T1566	1
T1566	6.4.2
T1566	6.4.1
T1566	8.6
T1566	8.5
T1566	8.3
T1566	8.2
T1566	8.1
T1566	2.1
T1566	12.3
T1580	9.3
T1580	9.1.1
T1580	8.7
T1580	8.6
T1580	8.5
T1580	8.2.2
T1580	8.2
T1580	8.1
T1580	7.2
T1580	7.1.4
T1580	7.1
T1580	6.4.2
T1580	2.1
T1580	12.3
T1580	11.4
T1580	10.6.2
T1580	10.6.1
T1580	2.2
T1580	10.6
T1580	8.3
T1078	9.3
T1078	8.7
T1078	8.5.1
T1078	7.2
T1078	7.1
T1078	6.4.2
T1078	2.3
T1078	12.3.9
T1078	12.3.8
T1078	12.3.10
T1087.004	8.5.1
T1087.004	8.1.5
T1087.004	2.3
T1087.004	12.3.9
T1087.004	12.3.8
T1087.004	12.3.10
T1098	8.7
T1098	8.6
T1098	8.5.1
T1098	8.5
T1098	8.3
T1098	8.2.2
T1098	8.2
T1098	8.1
T1098	7.1.4
T1098	6.4.2
T1098	2.3
T1098	2.1
T1098	12.3.9
T1098	12.3.8
T1098	12.3.10
T1098	12.3
T1098.004	8.6
T1098.004	8.5.1
T1098.004	8.5
T1098.004	8.3
T1098.004	8.2
T1098.004	2.3
T1098.004	2.1
T1098.004	12.3.9
T1098.004	12.3.8
T1098.004	12.3.10
T1098.004	12.3
T1136	9.3
T1136	8.7
T1136	8.6
T1136	8.5.1
T1136	8.5
T1136	8.3
T1136	8.2.2
T1136	8.2
T1136	8.1.5
T1136	8.1
T1136	7.2
T1136	7.1.4
T1136	7.1
T1136	6.4.2
T1136	2.3
T1136	2.1
T1136	12.3.9
T1136	12.3.8
T1136	12.3.10
T1136	12.3
T1190	8.5.1
T1190	2.3
T1190	12.3.9
T1190	12.3.8
T1190	12.3.10
T1525	8.5.1
T1525	2.3
T1525	12.3.9
T1525	12.3.8
T1525	12.3.10
T1538	8.5.1
T1538	8.1.5
T1538	2.3
T1538	12.3.9
T1538	12.3.8
T1538	12.3.10
T1550	9.3
T1550	8.7
T1550	8.6
T1550	8.5.1
T1550	8.5
T1550	8.3
T1550	8.2.2
T1550	8.2
T1550	8.1.5
T1550	8.1
T1550	7.2
T1550	7.1.4
T1550	7.1
T1550	6.4.2
T1550	2.3
T1550	2.1
T1550	12.3.9
T1550	12.3.8
T1550	12.3.10
T1550	12.3
T1552	9.3
T1552	8.7
T1552	8.6
T1552	8.5.1
T1552	8.5
T1552	8.3
T1552	8.2.2
T1552	8.2
T1552	8.1.5
T1552	8.1
T1552	7.2
T1552	7.1.4
T1552	7.1
T1552	6.4.2
T1552	2.3
T1552	2.1
T1552	12.3.9
T1552	12.3.8
T1552	12.3.10
T1552	12.3
T1552.001	8.5.1
T1552.001	2.3
T1552.001	12.3.9
T1552.001	12.3.8
T1552.001	12.3.10
T1562	9.3
T1562	8.7
T1562	8.6
T1562	8.5.1
T1562	8.5
T1562	8.3
T1562	8.2.2
T1562	8.2
T1562	8.1.5
T1562	8.1
T1562	7.2
T1562	7.1.4
T1562	7.1
T1562	6.4.2
T1562	2.3
T1562	2.1
T1562	12.3.9
T1562	12.3.8
T1562	12.3.10
T1562	12.3
T1562.001	8.5.1
T1562.001	2.3
T1562.001	12.3.9
T1562.001	12.3.8
T1562.001	12.3.10
T1562.007	8.5.1
T1562.007	2.3
T1562.007	12.3.9
T1562.007	12.3.8
T1562.007	12.3.10
T1562.008	8.5.1
T1562.008	2.3
T1562.008	12.3.9
T1562.008	12.3.8
T1562.008	12.3.10
T1578	9.3
T1578	8.7
T1578	8.6
T1578	8.5.1
T1578	8.5
T1578	8.3
T1578	8.2.2
T1578	8.2
T1578	8.1.5
T1578	8.1
T1578	7.2
T1578	7.1.4
T1578	7.1
T1578	6.4.2
T1578	2.3
T1578	2.1
T1578	12.3.9
T1578	12.3.8
T1578	12.3.10
T1578	12.3
T1578.001	9.3
T1578.001	8.7
T1578.001	8.6
T1578.001	8.5.1
T1578.001	8.5
T1578.001	8.3
T1578.001	8.2.2
T1578.001	8.2
T1578.001	8.1.5
T1578.001	8.1
T1578.001	7.2
T1578.001	7.1.4
T1578.001	7.1
T1578.001	6.4.2
T1578.001	2.3
T1578.001	2.1
T1578.001	12.3.9
T1578.001	12.3.8
T1578.001	12.3.10
T1578.001	12.3
T1578.002	9.3
T1578.002	8.7
T1578.002	8.6
T1578.002	8.5.1
T1578.002	8.5
T1578.002	8.3
T1578.002	8.2.2
T1578.002	8.2
T1578.002	8.1.5
T1578.002	8.1
T1578.002	7.2
T1578.002	7.1.4
T1578.002	7.1
T1578.002	6.4.2
T1578.002	2.3
T1578.002	2.1
T1578.002	12.3.9
T1578.002	12.3.8
T1578.002	12.3.10
T1578.002	12.3
T1578.003	9.3
T1578.003	8.7
T1578.003	8.6
T1578.003	8.5.1
T1578.003	8.5
T1578.003	8.3
T1578.003	8.2.2
T1578.003	8.2
T1578.003	8.1.5
T1578.003	8.1
T1578.003	7.2
T1578.003	7.1.4
T1578.003	7.1
T1578.003	6.4.2
T1578.003	2.3
T1578.003	2.1
T1578.003	12.3.9
T1578.003	12.3.8
T1578.003	12.3.10
T1578.003	12.3
T1580	8.5.1
T1580	8.1.5
T1580	2.3
T1580	12.3.9
T1580	12.3.8
T1580	12.3.10
T1204	9.9.3
T1204	8.4
T1204	7.3
T1204	6.7
T1204	12.6
T1204	12.4
T1528	8.4
T1528	7.3
T1528	12.6
T1528	12.4
T1552	9.9.3
T1552	8.4
T1552	7.3
T1552	6.7
T1552	12.6
T1552	12.4
T1552.001	8.4
T1552.001	7.3
T1552.001	12.6
T1552.001	12.4
T1566	8.4
T1566	7.3
T1566	6.7
T1566	12.6
T1566	12.4
T1552	12.5
T1552	1.1.5
T1552.001	12.5
T1552.001	1.1.5
T1562.008	12.10.5 
T1552	11.5.1
T1552	12.5.2
T1552	12.10.5
T1552	12.1
T1552	10.8
T1552	10.6.3
T1552	10.6
T1552	10.1
T1136	1.1.3
T1136	1.1.2
T1040	2.2
T1040	1.2
T1087.004	1.2
T1110	2.2
T1110	1.2
T1136	2.2
T1136	1.2
T1535	2.2
T1535	1.2
T1552	2.2
T1552	1.2
T1562	2.2
T1562	1.2
T1491	9.5.1
T1491	12.10.2
T1491	12.10.1
T1491	12.1
T1552	12.10.6
T1552	12.10.1
T1046	6.7
T1046	6.6
T1046	6.4
T1046	6.3
T1098	6.7
T1098	6.6
T1098	6.5
T1098	6.4
T1098	6.3
T1098.001	6.7
T1098.001	6.6
T1098.001	6.5
T1098.001	6.4
T1098.001	6.3
T1136	6.7
T1136	6.6
T1136	6.5
T1136	6.4
T1136	6.3
T1136.003	6.7
T1136.003	6.6
T1136.003	6.5
T1136.003	6.4
T1136.003	6.3
T1199	6.7
T1199	6.6
T1199	6.5
T1199	6.4
T1199	6.3
T1204	7.2
T1204	7.1
T1204	12.5
T1204	1.1.5
T1528	12.5
T1528	1.1.5
T1566	7.2
T1566	7.1
T1566	12.5
T1566	1.1.5
T1552	9.6.1
T1552	6.1
T1552	12.8
T1552	12.2
T1552.001	9.6.1
T1566	11.1.2
T1562.008	11.1.2
T1562.007	11.1.2
T1562.001	11.1.2
T1552.005	11.1.2
T1552.001	11.1.2
T1550.001	11.1.2
T1537	11.1.2
T1528	11.1.2
T1525	11.1.2
T1499.004	11.1.2
T1499.003	11.1.2
T1499.002	11.1.2
T1204.003	11.1.2
T1201	11.1.2
T1136.003	11.1.2
T1110.004	11.1.2
T1110.003	11.1.2
T1110.002	11.1.2
T1110.001	11.1.2
T1098.001	11.1.2
T1098	11.1.2
T1078.004	11.1.2
T1078.001	11.1.2
T1040	11.1.2
T1530	11.1.2
T1190	11.1.2
T1189	11.1.2
T1098.004	11.1.2
T1046	11.1.2
T1499.004	2.1
T1499.003	2.1
T1499.002	2.1
T1491.002	2.1
T1486	2.1
T1485	2.1
T1204.003	2.1
T1201	2.1
T1189	2.1
T1119	2.1
T1046	2.1
T1204.003	8.1
T1201	8.1
T1189	8.1
T1046	8.1
T1499.004	8.2
T1499.003	8.2
T1499.002	8.2
T1491.002	8.2
T1486	8.2
T1485	8.2
T1204.003	8.2
T1201	8.2
T1189	8.2
T1119	8.2
T1046	8.2
T1499.004	8.5
T1499.003	8.5
T1499.002	8.5
T1491.002	8.5
T1486	8.5
T1485	8.5
T1204.003	8.5
T1201	8.5
T1189	8.5
T1119	8.5
T1046	8.5
T1499.004	8.6
T1499.003	8.6
T1499.002	8.6
T1491.002	8.6
T1486	8.6
T1485	8.6
T1204.003	8.6
T1201	8.6
T1189	8.6
T1119	8.6
T1046	8.6
T1499.004	12.3
T1499.003	12.3
T1499.002	12.3
T1491.002	12.3
T1486	12.3
T1485	12.3
T1204.003	12.3
T1201	12.3
T1189	12.3
T1119	12.3
T1046	12.3
T1190	1.4
T1189	1.4
T1491.002	9.5
T1491	9.5
T1486	9.5
T1485	9.5
T1552	9.5
T1136.003	9.5
T1136	9.5
T1098.001	9.5
T1098	9.5
T1552	9.5.1
T1530	9.5.1
T1136.003	9.5.1
T1136	9.5.1
T1098.001	9.5.1
T1098	9.5.1
T1199	1.1.6
T1046	1.1.6
T1136.003	1.1.6
T1136	1.1.6
T1098.001	1.1.6
T1098	1.1.6
T1190	1.1.6
T1199	1.2.3
T1046	1.2.3
T1136.003	1.2.3
T1136	1.2.3
T1098.001	1.2.3
T1098	1.2.3
T1190	1.2.3
T1199	2.2.2
T1046	2.2.2
T1136.003	2.2.2
T1136	2.2.2
T1098.001	2.2.2
T1098	2.2.2
T1190	2.2.2
T1499.004	8.3
T1499.003	8.3
T1499.002	8.3
T1498.002	8.3
T1498.001	8.3
T1204.003	8.3
T1201	8.3
T1189	8.3
T1046	8.3
T1190	10.5.3
T1552.005	10.5.3
T1552	10.5.3
T1552	10.6.1
T1566	1.1.4
T1552.005	1.1.4
T1552.001	1.1.4
T1537	1.1.4
T1530	1.1.4
T1499.004	1.1.4
T1499.003	1.1.4
T1499.002	1.1.4
T1498.002	1.1.4
T1498.001	1.1.4
T1204.003	1.1.4
T1199	1.1.4
T1190	1.1.4
T1189	1.1.4
T1136.003	1.1.4
T1098.001	1.1.4
T1046	1.1.4
T1566	1.3.2
T1552.005	1.3.2
T1552.001	1.3.2
T1537	1.3.2
T1530	1.3.2
T1499.004	1.3.2
T1499.003	1.3.2
T1499.002	1.3.2
T1498.002	1.3.2
T1498.001	1.3.2
T1204.003	1.3.2
T1199	1.3.2
T1190	1.3.2
T1189	1.3.2
T1136.003	1.3.2
T1098.001	1.3.2
T1046	1.3.2
T1566	1.3.3
T1552.005	1.3.3
T1552.001	1.3.3
T1537	1.3.3
T1530	1.3.3
T1499.004	1.3.3
T1499.003	1.3.3
T1499.002	1.3.3
T1498.002	1.3.3
T1498.001	1.3.3
T1204.003	1.3.3
T1199	1.3.3
T1190	1.3.3
T1189	1.3.3
T1136.003	1.3.3
T1098.001	1.3.3
T1046	1.3.3
T1566	1.3.4
T1552.005	1.3.4
T1552.001	1.3.4
T1537	1.3.4
T1530	1.3.4
T1499.004	1.3.4
T1499.003	1.3.4
T1499.002	1.3.4
T1498.002	1.3.4
T1498.001	1.3.4
T1204.003	1.3.4
T1199	1.3.4
T1190	1.3.4
T1189	1.3.4
T1136.003	1.3.4
T1098.001	1.3.4
T1046	1.3.4
T1566	1.3.5
T1552.005	1.3.5
T1552.001	1.3.5
T1537	1.3.5
T1530	1.3.5
T1499.004	1.3.5
T1499.003	1.3.5
T1499.002	1.3.5
T1498.002	1.3.5
T1498.001	1.3.5
T1204.003	1.3.5
T1199	1.3.5
T1190	1.3.5
T1189	1.3.5
T1136.003	1.3.5
T1098.001	1.3.5
T1046	1.3.5
T1566	6.6
T1552.005	6.6
T1537	6.6
T1499.004	6.6
T1499.003	6.6
T1499.002	6.6
T1498.002	6.6
T1498.001	6.6
T1204.003	6.6
T1189	6.6
T1204	11.4
T1204	11.1
T1204	12.6.1
T1528	12.6.1
T1566	12.6.1
T1204	12.6.2
T1528	12.6.2
T1566	12.6.2
T1552.001	12.10.4
T1552	12.10.4
T1552	6.5
T1098.004	6.3
T1552	6.3
T1190	6.4.1
T1136.003	6.4.1
T1098.001	6.4.1
T1098	6.4.1
T1552.001	6.5.1
T1552	6.5.1
T1078	6.5.1
T1552.001	6.5.2
T1552	6.5.2
T1078	6.5.2
T1552.001	6.5.3
T1552	6.5.3
T1078	6.5.3
T1552.001	6.5.4
T1552	6.5.4
T1078	6.5.4
T1552.001	6.5.5
T1552	6.5.5
T1078	6.5.5
T1552.001	6.5.6
T1552	6.5.6
T1078	6.5.6
T1552.001	6.5.7
T1552	6.5.7
T1078	6.5.7
T1552.001	6.5.8
T1552	6.5.8
T1078	6.5.8
T1552.001	6.5.9
T1552	6.5.9
T1078	6.5.9
T1552.001	6.5.10
T1552	6.5.10
T1078	6.5.10
T1046	11.3.1
T1530	11.3.1
T1190	11.3.1
T1535	11.3.2
T1189	11.3.2
T1550.001	11.3.2
T1552.001	11.3.2
T1528	11.3.2
T1578.003	11.3.2
T1578.002	11.3.2
T1578.001	11.3.2
T1578	11.3.2
T1525	11.3.2
T1562.007	11.3.2
T1530	11.3.2
T1087.004	11.3.2
T1552.005	11.3.2
T1098.004	11.3.2
T1136	11.3.2
T1098	11.3.2
T1552	11.3.2
T1204	11.5
T1552.001	2.1.1
T1528	2.1.1
T1136.003	2.1.1
T1110.004	2.1.1
T1110.003	2.1.1
T1110.002	2.1.1
T1110.001	2.1.1
T1098.001	2.1.1
T1078.004	2.1.1
T1078	2.1.1
T1550.001	2.1.1
T1537	2.1.1
T1530	2.1.1
T1119	2.1.1
T1040	2.1.1
T1552.001	4.1
T1528	4.1
T1136.003	4.1
T1110.004	4.1
T1110.003	4.1
T1110.002	4.1
T1110.001	4.1
T1098.001	4.1
T1078.004	4.1
T1078	4.1
T1550.001	4.1
T1537	4.1
T1530	4.1
T1119	4.1
T1040	4.1
T1552.001	4.1.1
T1528	4.1.1
T1136.003	4.1.1
T1110.004	4.1.1
T1110.003	4.1.1
T1110.002	4.1.1
T1110.001	4.1.1
T1098.001	4.1.1
T1078.004	4.1.1
T1078	4.1.1
T1550.001	4.1.1
T1537	4.1.1
T1530	4.1.1
T1119	4.1.1
T1040	4.1.1
T1528	8.2.1
T1136.003	8.2.1
T1110.004	8.2.1
T1110.003	8.2.1
T1110.002	8.2.1
T1110.001	8.2.1
T1098.001	8.2.1
T1537	8.2.1
T1119	8.2.1
T1550.001	3.4
T1552	3.4
T1530	3.4
T1119	3.4
T1550.001	3.4.1 
T1552	3.4.1 
T1530	3.4.1 
T1119	3.4.1 
T1552	8.2.1
T1552	2.2.1
T1199	2.2.1
T1046	2.2.1
T1190	2.2.1
T1136.003	2.2.1
T1136	2.2.1
T1098.001	2.2.1
T1098	2.2.1
T1552	2.4
T1199	2.4
T1136	2.4
T1098	2.4
T1580	10.2.1
T1562.008	10.2.1
T1562.007	10.2.1
T1562.001	10.2.1
T1552.001	10.2.1
T1538	10.2.1
T1537	10.2.1
T1530	10.2.1
T1528	10.2.1
T1525	10.2.1
T1491.002	10.2.1
T1486	10.2.1
T1485	10.2.1
T1199	10.2.1
T1190	10.2.1
T1189	10.2.1
T1136.003	10.2.1
T1110.004	10.2.1
T1110.003	10.2.1
T1110.002	10.2.1
T1110.001	10.2.1
T1098.001	10.2.1
T1087.004	10.2.1
T1078.004	10.2.1
T1078.001	10.2.1
T1580	11.5
T1538	11.5
T1199	11.5
T1087.004	11.5
T1098.001	7.1.1
T1098	7.1.1
T1552.001	7.1.1
T1552	7.1.1
T1098.004	7.1.1
T1537	7.1.1
T1528	7.1.1
T1562.008	7.1.1
T1562.007	7.1.1
T1562.001	7.1.1
T1562	7.1.1
T1530	7.1.1
T1538	7.1.1
T1580	7.1.1
T1087.004	7.1.1
T1098.001	7.1.2
T1098	7.1.2
T1552.001	7.1.2
T1552	7.1.2
T1098.004	7.1.2
T1537	7.1.2
T1528	7.1.2
T1562.008	7.1.2
T1562.007	7.1.2
T1562.001	7.1.2
T1562	7.1.2
T1530	7.1.2
T1538	7.1.2
T1580	7.1.2
T1087.004	7.1.2
T1098.001	7.1.3
T1098	7.1.3
T1552.001	7.1.3
T1552	7.1.3
T1098.004	7.1.3
T1537	7.1.3
T1528	7.1.3
T1562.008	7.1.3
T1562.007	7.1.3
T1562.001	7.1.3
T1562	7.1.3
T1530	7.1.3
T1538	7.1.3
T1580	7.1.3
T1087.004	7.1.3
T1110	11.5
T1535	11.5
T1136	11.5
T1562	11.5
T1552	11.5
T1552	1.1.1
T1136	1.1.1
T1040	1.2.2
T1552.005	1.2.2
T1552	1.2.2
T1537	1.2.2
T1499.004	1.2.2
T1499.003	1.2.2
T1499.002	1.2.2
T1530	1.2.2
T1136.003	1.2.2
T1136	1.2.2
T1098.001	1.2.2
T1098	1.2.2
T1580	8.1.8
T1562.008	8.1.8
T1562.007	8.1.8
T1562.001	8.1.8
T1552.001	8.1.8
T1538	8.1.8
T1537	8.1.8
T1530	8.1.8
T1528	8.1.8
T1525	8.1.8
T1190	8.1.8
T1136.003	8.1.8
T1110.004	8.1.8
T1110.003	8.1.8
T1110.002	8.1.8
T1110.001	8.1.8
T1098.001	8.1.8
T1087.004	8.1.8
T1078.004	8.1.8
T1078.001	8.1.8
T1136	1.1.4
T1098	1.1.4
T1537	1.3.1
T1530	1.3.1
T1199	1.3.1
T1046	1.3.1
T1190	1.3.1
T1136.003	1.3.1
T1136	1.3.1
T1098.001	1.3.1
T1098	1.3.1
T1552.005	1.4
T1552	1.4
T1552	1.1.4
T1110	2.1
T1078.001	2.1.1
T1552	2.1.1
T1525	2.1.1
T1190	2.1.1
T1136	2.1.1
T1098	2.1.1
T1550	2.1.1
T1578.003	2.1.1
T1578.001	2.1.1
T1578.002	2.1.1
T1578	2.1.1
T1562.008	2.1.1
T1562.007	2.1.1
T1562.001	2.1.1
T1562	2.1.1
T1538	2.1.1
T1580	2.1.1
T1110	2.1.1
T1087.004	2.1.1
T1552.005	1.1.6
T1098.004	1.1.6
T1552.005	1.2.1
T1046	1.2.1
T1098.004	1.2.1
T1098	1.2.1
T1552.005	2.2.2
T1098.004	2.2.2
T1552.005	2.2.5
T1046	2.2.5
T1098.004	2.2.5
T1098	2.2.5
T1552.005	12.8
T1046	12.8
T1098.004	12.8
T1098	12.8
T1552.005	12.9
T1046	12.9
T1098.004	12.9
T1098	12.9
T1078	8.1.1
T1078.004	8.1.1
T1078	8.1.4
T1552	8.1.4
T1525	8.1.4
T1190	8.1.4
T1136.003	8.1.4
T1136	8.1.4
T1098.001	8.1.4
T1098	8.1.4
T1078.004	8.1.4
T1550	8.1.4
T1537	8.1.4
T1528	8.1.4
T1578.003	8.1.4
T1578.001	8.1.4
T1578.002	8.1.4
T1578	8.1.4
T1562.008	8.1.4
T1562.007	8.1.4
T1562.001	8.1.4
T1562	8.1.4
T1530	8.1.4
T1538	8.1.4
T1580	8.1.4
T1110.004	8.1.4
T1110	8.1.4
T1087.004	8.1.4
T1078.004	7.1.1
T1078	7.1.1
T1550	7.1.1
T1525	7.1.1
T1136.003	7.1.1
T1136	7.1.1
T1578.003	7.1.1
T1578.001	7.1.1
T1578.002	7.1.1
T1578	7.1.1
T1078.004	7.1.2
T1078	7.1.2
T1550	7.1.2
T1525	7.1.2
T1136.003	7.1.2
T1136	7.1.2
T1578.003	7.1.2
T1578.001	7.1.2
T1578.002	7.1.2
T1578	7.1.2
T1078.004	7.1.3
T1078	7.1.3
T1550	7.1.3
T1525	7.1.3
T1136.003	7.1.3
T1136	7.1.3
T1578.003	7.1.3
T1578.001	7.1.3
T1578.002	7.1.3
T1578	7.1.3
T1078	8.1.3
T1525	8.1.3
T1190	8.1.3
T1136.003	8.1.3
T1136	8.1.3
T1098.001	8.1.3
T1098	8.1.3
T1552.001	8.1.3
T1552	8.1.3
T1098.004	8.1.3
T1078.004	8.1.3
T1550	8.1.3
T1537	8.1.3
T1578.003	8.1.3
T1578.001	8.1.3
T1578.002	8.1.3
T1578	8.1.3
T1562.008	8.1.3
T1562.007	8.1.3
T1562.001	8.1.3
T1562	8.1.3
T1530	8.1.3
T1538	8.1.3
T1580	8.1.3
T1087.004	8.1.3
T1110	8.3
T1110	2.3
T1078.004	8.3.2
T1040	8.3.2
T1530	8.3.2
T1136.003	8.3.2
T1136	8.3.2
T1110.004	8.3.2
T1110.003	8.3.2
T1110.002	8.3.2
T1110.001	8.3.2
T1110	8.3.2
T1098.001	8.3.2
T1098	8.3.2
T1078.004	8.3.1
T1040	8.3.1
T1530	8.3.1
T1136.003	8.3.1
T1136	8.3.1
T1110.004	8.3.1
T1110.003	8.3.1
T1110.002	8.3.1
T1110.001	8.3.1
T1110	8.3.1
T1098.001	8.3.1
T1098	8.3.1
T1552	11.2.1
T1189	11.2.1
T1190	11.2.1
T1552	6.2
T1552	11.2
T1498	11.2
T1552.001	10.7
T1552	10.7
T1040	10.7
T1562.008	10.2
T1562.008	10.3
T1562.008	10.7
T1562.008	10.4
T1552.005	10.4
T1552	10.4
T1190	10.4
T1204	1.1.6
T1566	1.1.6
T1189	1.1.6
T1648	10.1
T1648	1.1
\.


                                                                                                                                                                                                                                                                                                    4449.dat                                                                                            0000600 0004000 0002000 00000010213 14362250176 0014261 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        TA0006	https://attack.mitre.org/tactics/TA0006/	Acceso a las credenciales	Credential Access	El uso de credenciales legítimas puede dar a los adversarios acceso a los sistemas, dificultar su detección y darles la oportunidad de crear más cuentas que les ayuden a conseguir sus objetivos.	Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.
TA0007	https://attack.mitre.org/tactics/TA0007/	Descubrimiento	Discovery	El descubrimiento consiste en técnicas que un adversario puede utilizar para obtener conocimientos sobre el sistema y la red interna, y orientarse antes de decidir cómo actuar.	Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network, and orient themselves before deciding how to act.
TA0008	https://attack.mitre.org/tactics/TA0008/	Movimiento lateral	Lateral Movement	El Movimiento Lateral consiste en técnicas que los adversarios utilizan para entrar y controlar sistemas remotos en una red.	Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network.
TA0010	https://attack.mitre.org/tactics/TA0010/	Exfiltración	Exfiltration	La exfiltración consiste en técnicas que los adversarios pueden utilizar para robar datos de su red.	Exfiltration consists of techniques that adversaries may use to steal data from your network.
TA0040	https://attack.mitre.org/tactics/TA0040/	Impacto	Impact	El impacto consiste en técnicas que los adversarios utilizan para interrumpir la disponibilidad o comprometer la integridad mediante la manipulación de los procesos empresariales y operativos.	Impact consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes.
TA0009	https://attack.mitre.org/tactics/TA0009/	Colección	Collection	La recopilación consiste en técnicas que los adversarios pueden utilizar para reunir información de interés para su objetivo.	Collection consists of techniques adversaries may use to gather information of interest to their goal.
TA0002	https://attack.mitre.org/tactics/TA0002/	Ejecución	Execution	La ejecución consiste en técnicas que dan lugar a un código controlado por el adversario que se ejecuta en un sistema local o remoto.	Execution consists of techniques that result in adversary-controlled code running on a local or remote system.
TA0005	https://attack.mitre.org/tactics/TA0005/	Evasión de la defensa	Defense Evasion	La evasión de la defensa consiste en las técnicas que los adversarios utilizan para evitar la detección a lo largo de su compromiso.	Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise.
TA0004	https://attack.mitre.org/tactics/TA0004/	Escalada de privilegios	Privilege Escalation	Esta táctica radica en técnicas que los enemigos utilizan para lograr permisos superiores. Los enfoques más comunes son aprovechar las debilidades del sistema, las desconfiguraciones y debilidades.	This tactic consists of techniques that adversaries use to gain higher-level permissions. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities.
TA0003	https://attack.mitre.org/tactics/TA0003/	Persistencia	Persistence	La persistencia radica en técnicas que los enemigos utilizan para mantener el acceso a los sistemas a pesar de los reinicios, los cambios de credenciales y otras interrupciones que cortaran su acceso.	Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access.
TA0001	https://attack.mitre.org/tactics/TA0001/	Acceso inicial	Initial Access	Los apoyos obtenidos mediante el acceso inicial pueden permitir el acceso continuo, como cuentas válidas y el uso de servicios remotos externos, o pueden ser limitado debido al cambio de contraseñas.	Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.
\.


                                                                                                                                                                                                                                                                                                                                                                                     4447.dat                                                                                            0000600 0004000 0002000 00000067231 14362250176 0014273 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        T1136.003	https://attack.mitre.org/techniques/T1136/003/	M1032 Multi-factor Authentication	Crear una cuenta: Cuenta en la nube	Create Account: Cloud Account	Los adversarios pueden crear una cuenta en la nube para mantener el acceso a los sistemas de la víctima.	Adversaries may create a cloud account to maintain access to victim systems
T1535	https://attack.mitre.org/techniques/T1535/	M1054 Software Configuration	Regiones de la nube no utilizadas/no admitidas	Unused/Unsupported Cloud Regions	Si un adversario crea recursos en una región no utilizada, puede ser capaz de operar sin ser detectado.	If an adversary creates resources in an unused region, they may be able to operate undetected
T1136	https://attack.mitre.org/techniques/T1136/	M1032 Multi-factor Authentication, M1030 Network Segmentation, M1026 Privileged Account Management	Crear una cuenta	Create Account	Los adversarios pueden crear una cuenta para mantener el acceso a los sistemas de la víctima.	Adversaries may create an account to maintain access to victim systems
T1552	https://attack.mitre.org/techniques/T1552/	M1041 Encrypt Sensitive Information, M1037 Filter Network Traffic, M1027 Password Policies, M1026 Privileged Account Management	Credenciales no garantizadas	Unsecured Credentials	Los adversarios pueden buscar en los sistemas comprometidos para encontrar y obtener credenciales almacenadas de forma insegura.	Adversaries may search compromised systems to find and obtain insecurely stored credentials
T1204	https://attack.mitre.org/techniques/T1204/	M1017 User Training	Ejecución por parte del usuario	User Execution	Un adversario puede depender de acciones específicas de un usuario para obtener la ejecución.	An adversary may rely upon specific actions by a user in order to gain execution.
T1204.003	https://attack.mitre.org/techniques/T1204/003/	M1045 Code Signing, M1047 Audit	Ejecución por parte del usuario: Imagen maliciosa	User Execution: Malicious Image	Las imágenes con respaldo pueden subirse a un repositorio público a través de Upload Malware, y los usuarios pueden entonces descargar y desplegar una instancia o contenedor.	Backdoored images may be uploaded to a public repository via Upload Malware, and users may then download and deploy an instance or container
T1098	https://attack.mitre.org/techniques/T1098/	M1032 Multi-factor Authentication, M1026 Privileged Account Management, M1030 Network Segmentation	Manipulación de cuentas	Account Manipulation	Los adversarios pueden manipular las cuentas para mantener el acceso a los sistemas de las víctimas.	Adversaries may manipulate accounts to maintain access to victim systems
T1201	https://attack.mitre.org/techniques/T1201/	Detect	Descubrimiento de la política de contraseñas	Password Policy Discovery	Los adversarios pueden intentar acceder a información detallada sobre la política de contraseñas utilizada en una red empresarial o en un entorno de nube.	Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment
T1562	https://attack.mitre.org/techniques/T1562/	M1018 User Account Management	Deterioro de las defensas	Impair Defenses	Los adversarios pueden modificar maliciosamente los componentes del entorno de la víctima para obstaculizar o desactivar los mecanismos de defensa.	Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms
T1562.001	https://attack.mitre.org/techniques/T1562/001/	M1018 User Account Management	Deteriorar las defensas: Desactivar o modificar las herramientas	Impair Defenses: Disable or Modify Tools	Los adversarios pueden modificar y/o desactivar las herramientas de seguridad para evitar la posible detección de su malware/herramientas y actividades.	Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities
T1562.008	https://attack.mitre.org/techniques/T1562/008/	M1018 User Account Management	Deteriorar las defensas: Desactivar los registros en la nube	Impair Defenses: Disable Cloud Logs	Si un adversario tiene suficientes permisos, puede desactivar el registro para evitar la detección de sus actividades.	If an adversary has sufficient permissions, they can disable logging to avoid detection of their activities
T1578.001	https://attack.mitre.org/techniques/T1578/001/	M1047 Audit, M1018 User Account Management	Modificar la infraestructura de Cloud Compute: Crear una instantánea	Modify Cloud Compute Infrastructure: Create Snapshot	Un adversario puede crear una instantánea o una copia de seguridad de los datos dentro de una cuenta en la nube para evadir las defensas.	An adversary may create a snapshot or data backup within a cloud account to evade defenses
T1110	https://attack.mitre.org/techniques/T1110/	M1032 Multi-factor Authentication, M1027 Password Policies, M1018 User Account Management	Fuerza bruta	Brute Force	Los adversarios pueden utilizar técnicas de fuerza bruta para acceder a las cuentas cuando se desconocen las contraseñas o cuando se obtienen los hashes de las mismas.	Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained
T1098.004	https://attack.mitre.org/techniques/T1098/004/	M1022 Restrict File and Directory Permissions, M1042 Disable or Remove Feature or Program	Manipulación de cuentas: Claves autorizadas SSH	Account Manipulation: SSH Authorized Keys	Los adversarios pueden modificar el archivo SSH authorized_keys para mantener la persistencia en un host víctima.	Adversaries may modify the SSH authorized_keys file to maintain persistence on a victim host
T1078	https://attack.mitre.org/techniques/T1078/	M1027 Password Policies, M1018 User Account Management, M1017 User Training	Cuentas válidas	Valid Accounts	Las credenciales comprometidas pueden utilizarse para eludir los controles de acceso.	Compromised credentials may be used to bypass access controls
T1621	https://attack.mitre.org/techniques/T1621/	M1036 Account Use Policies, M1032 Multi-factor Authentication, M1017 User Training	Generación de solicitudes de autenticación multifactoriales	Multi-Factor Authentication Request Generation	Los adversarios pueden abusar de la generación automática de notificaciones push a los servicios MFA para que el usuario conceda acceso a su cuenta.	Adversaries may abuse the automatic generation of push notifications to MFA services to have the user grant access to their account
T1087.004	https://attack.mitre.org/techniques/T1087/004/	M1018 User Account Management	Descubrimiento de la cuenta: Cuenta en la nube	Account Discovery: Cloud Account	Los adversarios pueden intentar obtener un listado de cuentas en la nube.	Adversaries may attempt to get a listing of cloud accounts
T1538	https://attack.mitre.org/techniques/T1538/	M1018 User Account Management	Cuadro de mando de los servicios en la nube	Cloud Service Dashboard	Un adversario puede ser capaz de enumerar la información a través del panel gráfico. Esto permite al adversario obtener información sin realizar ninguna solicitud de API.	An adversary may be able to enumerate information via the graphical dashboard. This allows the adversary to gain information without making any API requests
T1119	https://attack.mitre.org/techniques/T1119/	M1041 Encrypt Sensitive Information	Recogida automatizada	Automated Collection	Esta técnica puede incorporar el uso de otras técnicas como el descubrimiento de objetos de almacenamiento en la nube para identificar recursos en entornos de nube.	This technique may incorporate use of other techniques such as Cloud Storage Object Discovery to identify resources in cloud environments
T1485	https://attack.mitre.org/techniques/T1485/	M1053 Data Backup	Destrucción de datos	Data Destruction	Los adversarios pueden intentar sobrescribir archivos y directorios con datos generados aleatoriamente para hacerlos irrecuperables.	Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable
T1491	https://attack.mitre.org/techniques/T1491/	M1053 Data Backup	Desplazamiento	Defacement	Los adversarios pueden modificar el contenido visual disponible interna o externamente en una red empresarial, afectando así a la integridad del contenido original.	Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content
T1498.002	https://attack.mitre.org/techniques/T1498/002/	M1037 Filter Network Traffic	Denegación de servicio en la red: Amplificación de la reflexión	Network Denial of Service: Reflection Amplification	Los adversarios pueden intentar provocar una denegación de servicio (DoS) reflejando un alto volumen de tráfico de red hacia un objetivo.	Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target.
T1528	https://attack.mitre.org/techniques/T1528/	M1018 User Account Management	Robar el token de acceso a la aplicación	Steal Application Access Token	Los adversarios pueden robar los tokens de acceso a las aplicaciones como medio de adquirir credenciales para acceder a sistemas y recursos remotos.	Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources
T1078.001	https://attack.mitre.org/techniques/T1078/001/	M1027 Password Policies	Cuentas válidas: Cuentas por defecto	Valid Accounts: Default Accounts	Los adversarios pueden obtener y abusar de las credenciales de una cuenta por defecto como medio para obtener Acceso Inicial, Persistencia, Escalada de Privilegios o Evasión de Defensa.	Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion
T1098.001	https://attack.mitre.org/techniques/T1098/001/	M1032 Multi-factor Authentication, M1026 Privileged Account Management	Manipulación de cuentas: Credenciales adicionales en la nube	Account Manipulation: Additional Cloud Credentials	La manipulación de cuentas puede consistir en cualquier acción que preserve el acceso del adversario a una cuenta comprometida, como la modificación de credenciales o grupos de permisos.	Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups
T1525	https://attack.mitre.org/techniques/T1525/	M1045 Code Signing, M1047 Audit	Imagen interna del implante	Implant Internal Image	Los adversarios pueden implantar imágenes de la nube o del contenedor con código malicioso para establecer la persistencia después de obtener acceso a un entorno.	Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment
T1566	https://attack.mitre.org/techniques/T1566/	M1021 Restrict Web-Based Content	Phishing	Phishing	Los adversarios pueden enviar mensajes de phishing para acceder a los sistemas de las víctimas.	Adversaries may send phishing messages to gain access to victim systems
T1550	https://attack.mitre.org/techniques/T1550/	M1026 Privileged Account Management, M1018 User Account Management	Utilizar material de autenticación alternativo	Use Alternate Authentication Material	Los adversarios pueden utilizar material de autenticación alternativo para moverse lateralmente dentro de un entorno y eludir los controles normales de acceso al sistema.	Adversaries may use alternate authentication material in order to move laterally within an environment and bypass normal system access controls
T1550.001	https://attack.mitre.org/techniques/T1550/001/	M1026 Privileged Account Management	Utilizar material de autenticación alternativo: Token de acceso a la aplicación	Use Alternate Authentication Material: Application Access Token	Los adversarios pueden utilizar tokens de acceso a aplicaciones robados para eludir el proceso típico de autenticación y acceder a cuentas, información o servicios restringidos en sistemas remotos.	Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems
T1648	https://attack.mitre.org/techniques/T1648/	M1018 User Account Management	Ejecución sin servidor	Serverless Execution	Los adversarios pueden abusar de la computación sin servidor, la integración y los servicios de automatización para ejecutar código arbitrario en entornos de nube.	Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments
T1562.007	https://attack.mitre.org/techniques/T1562/007/	M1018 User Account Management	Deteriorar las defensas: Desactivar o modificar el cortafuegos de la nube	Impair Defenses: Disable or Modify Cloud Firewall	Un adversario puede introducir nuevas reglas o políticas de firewall para permitir el acceso a un entorno de nube víctima.	An adversary may introduce new firewall rules or policies to allow access into a victim cloud environment
T1578	https://attack.mitre.org/techniques/T1578/	M1047 Audit, M1018 User Account Management	Modificar la infraestructura de computación en nube	Modify Cloud Compute Infrastructure	Los permisos obtenidos a partir de la modificación de los componentes de la infraestructura pueden eludir las restricciones que impiden el acceso a la infraestructura existente.	Permissions gained from the modification of infrastructure components may bypass restrictions that prevent access to existing infrastructure
T1578.003	https://attack.mitre.org/techniques/T1578/003/	M1047 Audit, M1018 User Account Management	Modificar la infraestructura de computación en nube: Borrar instancia de nube	Modify Cloud Compute Infrastructure: Delete Cloud Instance	Un adversario puede eliminar una instancia de la nube después de haber realizado actividades maliciosas en un intento de evadir la detección y eliminar la evidencia de su presencia.	An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence
T1040	https://attack.mitre.org/techniques/T1040/	M1041 Encrypt Sensitive Information	Escaneado de la red	Network Sniffing	El sniffing de red se refiere a la utilización de la interfaz de red de un sistema para supervisar o capturar la información enviada a través de una conexión alámbrica o inalámbrica.	Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection
T1110.001	https://attack.mitre.org/techniques/T1110/001/	M1032 Multi-factor Authentication	Fuerza bruta: Adivinar la contraseña	Brute Force: Password Guessing	Sin conocer la contraseña de una cuenta, un adversario puede optar por adivinar sistemáticamente la contraseña mediante un mecanismo repetitivo o iterativo.	Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism
T1078.004	https://attack.mitre.org/techniques/T1078/004/	M1032 Multi-factor Authentication, M1027 Password Policies, M1026 Privileged Account Management	Cuentas válidas: Cuentas en la nube	Valid Accounts: Cloud Accounts	Los adversarios pueden obtener y abusar de las credenciales de una cuenta en la nube como medio para obtener Acceso Inicial, Persistencia, Escalada de Privilegios o Evasión de la Defensa.	Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion
T1110.003	https://attack.mitre.org/techniques/T1110/003/	M1032 Multi-factor Authentication	Fuerza bruta: Pulverización de contraseñas	Brute Force: Password Spraying	Los adversarios pueden utilizar una única o pequeña lista de contraseñas de uso común contra muchas cuentas diferentes para intentar adquirir credenciales de cuentas válidas.	Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials
T1552.001	https://attack.mitre.org/techniques/T1552/001/	M1041 Encrypt Sensitive Information	Credenciales no seguras: Credenciales en archivos	Unsecured Credentials: Credentials In Files	Los adversarios pueden buscar en los sistemas de archivos locales y en los archivos compartidos remotos archivos que contengan credenciales almacenadas de forma insegura.	Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials
T1552.005	https://attack.mitre.org/techniques/T1552/005/	M1041 Encrypt Sensitive Information	Credenciales no seguras: API de metadatos de instancias en la nube	Unsecured Credentials: Cloud Instance Metadata API	Los adversarios pueden intentar acceder a la API de metadatos de las instancias de la nube para recopilar credenciales y otros datos sensibles.	Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data
T1526	https://attack.mitre.org/techniques/T1526/	Cannot be easily mitigated	Descubrimiento de servicios en la nube	Cloud Service Discovery	Un adversario puede intentar enumerar los servicios en la nube que se ejecutan en un sistema después de obtener el acceso.	An adversary may attempt to enumerate the cloud services running on a system after gaining access
T1580	https://attack.mitre.org/techniques/T1580/	M1018 User Account Management	Descubrimiento de la infraestructura en la nube	Cloud Infrastructure Discovery	Un adversario puede intentar descubrir la infraestructura y los recursos disponibles en un entorno de infraestructura como servicio (IaaS).	An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment
T1110.004	https://attack.mitre.org/techniques/T1110/004/	M1032 Multi-factor Authentication	Fuerza bruta: Relleno de credenciales	Brute Force: Credential Stuffing	Los enemigos pueden usar las credenciales obtenidas a partir de los volcados de brechas de cuentas no relacionadas para obtener acceso a las cuentas objetivo mediante la superposición de credenciales.	Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap
T1619	https://attack.mitre.org/techniques/T1619/	M1018 User Account Management	Descubrimiento de objetos de almacenamiento en la nube	Cloud Storage Object Discovery	Los enemigos pueden enumerar objetos en la infraestructura de almacenamiento en cloud y utilizar esta información durante el descubrimiento automático para dar forma a los comportamientos posteriores.	Adversaries may enumerate objects in cloud storage infrastructure and use this information during automated discovery to shape follow-on behaviors
T1537	https://attack.mitre.org/techniques/T1537/	M1018 User Account Management	Transferencia de datos a la cuenta en la nube	Transfer Data to Cloud Account	Los enemigos pueden exfiltrar datos trasladándolo a otra cuenta en la nube que controlen para evitar las típicas transferencias/descargas de archivos y la detección de la exfiltración basada en la red	Adversaries may exfiltrate data by transferring the data to another cloud account they control to avoid typical file transfers/downloads and network-based exfiltration detection
T1486	https://attack.mitre.org/techniques/T1486/	M1053 Data Backup	Datos encriptados para el impacto	Data Encrypted for Impact	Los adversarios pueden cifrar los datos en los sistemas objetivo o en un gran número de sistemas en una red para interrumpir la disponibilidad de los recursos del sistema y de la red.	Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources
T1498	https://attack.mitre.org/techniques/T1498/	M1037 Filter Network Traffic	Denegación de servicio en la red	Network Denial of Service	Los adversarios pueden realizar ataques de denegación de servicio (DoS) en la red para degradar o bloquear la disponibilidad de los recursos objetivo para los usuarios.	Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users
T1498.001	https://attack.mitre.org/techniques/T1498/001/	M1037 Filter Network Traffic	Denegación de servicio en la red: Inundación directa de la red	Network Denial of Service: Direct Network Flood	Los adversarios pueden intentar provocar una denegación de servicio (DoS) enviando directamente un gran volumen de tráfico de red a un objetivo.	Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target
T1531	https://attack.mitre.org/techniques/T1531/	Cannot be easily mitigated	Eliminación del acceso a la cuenta	Account Access Removal	Los adversarios pueden interrumpir la disponibilidad de los recursos del sistema y de la red inhibiendo el acceso a las cuentas utilizadas por los usuarios legítimos.	Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users
T1189	https://attack.mitre.org/techniques/T1189/	M1021\tRestrict Web-Based Content, M1050 Exploit Protection, M1051 Update Software	Compromiso de la unidad	Drive-by Compromise	El navegador web del usuario suele ser el objetivo de la explotación, pero los adversarios también pueden utilizar sitios web comprometidos que adquieren Application Access Token.	The user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites acquiring Application Access Token
T1499.002	https://attack.mitre.org/techniques/T1499/002/	M1037 Filter Network Traffic	Denegación de servicio en punto final: Inundación por agotamiento del servicio	Endpoint Denial of Service: Service Exhaustion Flood	Los adversarios pueden dirigirse a los diferentes servicios de red proporcionados por los sistemas para llevar a cabo una denegación de servicio (DoS).	Adversaries may target the different network services provided by systems to conduct a denial of service (DoS)
T1499.003	https://attack.mitre.org/techniques/T1499/003/	M1037 Filter Network Traffic	Denegación de servicio en punto final: Inundación por agotamiento de aplicación	Endpoint Denial of Service: Application Exhaustion Flood	Los adversarios pueden apuntar a características de recursos intensivos de las aplicaciones para causar una negación de servicio (DoS), negando la disponibilidad de esas aplicaciones.	Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications
T1491.002	https://attack.mitre.org/techniques/T1491/002/	M1053 Data Backup	Desplazamiento: Desfiguración externa	Defacement: External Defacement	Un enemigo puede desfigurar sistemas externos a una organización. La desfiguración externa puede hacer que los usuarios desconfíen de los sistemas y cuestionen/desacrediten la integridad del sistema.	An adversary may deface systems external to an organization. External Defacement may ultimately cause users to distrust the systems and to question/discredit the systemâ€™s integrity
T1199	https://attack.mitre.org/techniques/T1199/	M1030 Network Segmentation	Relación de confianza	Trusted Relationship	El acceso a través de un tercero de confianza explota una conexión existente que puede no estar protegida o que recibe menos escrutinio que los mecanismos estándar para obtener acceso a una red.	Access through trusted third party relationship exploits an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network
T1578.002	https://attack.mitre.org/techniques/T1578/002/	M1047 Audit, M1018 User Account Management	Modificación de Infraestructura en la Nube: Crear una instancia de nube	Modify Cloud Compute Infrastructure: Create Cloud Instance	Un adversario puede crear una nueva instancia o máquina virtual (VM) dentro del servicio de computación de una cuenta en la nube para evadir las defensas.	An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses
T1499.004	https://attack.mitre.org/techniques/T1499/004/	M1037 Filter Network Traffic	Denegación de servicio en punto final: Explotación de aplicaciones o sistemas	Endpoint Denial of Service: Application or System Exploitation	Los adversarios pueden explotar las vulnerabilidades del software que pueden hacer que una aplicación o un sistema se bloquee y deniegue la disponibilidad a los usuarios.	Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users
T1578.004	https://attack.mitre.org/techniques/T1578/004/	M1047 Audit, M1018 User Account Management	Modificar la infraestructura de computación en nube: Revertir Instancia de Nube	Modify Cloud Compute Infrastructure: Revert Cloud Instance	Un enemigo puede revertir los cambios realizados en una instancia del cloud después de haber realizado actividades maliciosas en un intento de evadir la detección y eliminar la evidencia de su figura.	An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence
T1496	https://attack.mitre.org/techniques/T1496/	Cannot be easily mitigated	Secuestro de recursos	Resource Hijacking	Los enemigos pueden aprovechar los recursos de los sistemas cooptados para resolver problemas que requieren muchos recursos, puede afectar a la disponibilidad del sistema y/o del servicio alojado.	Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems, which may impact system and/or hosted service availability
T1530	https://attack.mitre.org/techniques/T1530/	M1022 Restrict File and Directory Permissions	Datos del objeto de almacenamiento en la nube	Data from Cloud Storage Object	Los enemigos pueden acceder a los datos desde un almacenamiento en la nube mal protegido. Se puede utilizar las API de cloud para recuperar los datos del almacenamiento en línea	Adversaries may access data from improperly secured cloud storage. Data from online data storage such as Amazon S3 can be retrieved directly using the cloud provider´s APIs
T1110.002	https://attack.mitre.org/techniques/T1110/002/	M1032 Multi-factor Authentication	Fuerza bruta: Descifrado de contraseñas	Brute Force: Password Cracking	Los enemigos pueden utiliza fuerza bruta para recuperar credenciales utilizables, como las contraseñas en texto plano, cuando se obtiene material de credenciales como los hashes de las contraseñas.	Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained
T1190	https://attack.mitre.org/techniques/T1190/	M1051 Update Software, M1030 Network Segmentation, M1048 Application Isolation and Sandboxing	Explotar la aplicación de cara al público	Exploit Public-Facing Application	Los enemigos pueden aprovecharse de una debilidad en un ordenador o programa orientado a Internet utilizando software, datos o comandos con el fin de provocar una conducta no deseado o imprevisto.	Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior
T1046	https://attack.mitre.org/techniques/T1046/	M1030 Network Segmentation, M1031 Network Intrusion Prevention	Descubrimiento de servicios de red	Network Service Discovery	Los enemigos pueden conocer los servicios que se ejecutan en los hosts remotos, que pueden ser vulnerables a la explotación remota. Se puede obtener esta información haciendo escaneos de puertos.	Adversaries may attempt to get a listing of services running on remote hosts, that may be vulnerable to remote exploitation. Common methods to acquire this information include port scans
\.


                                                                                                                                                                                                                                                                                                                                                                       4454.dat                                                                                            0000600 0004000 0002000 00000010547 14362250176 0014267 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        AC-10	CONCURRENT SESSION CONTROL
AC-11	SESSION LOCK
AC-12	SESSION TERMINATION
AC-14	PERMITTED ACTIONS WITHOUT IDENTIFICATION OR AUTHENTICATION
AC-16	SECURITY ATTRIBUTES
AC-17	REMOTE ACCESS
AC-18	WIRELESS ACCESS
AC-19	ACCESS CONTROL FOR MOBILE DEVICES
AC-2	ACCOUNT MANAGEMENT
AC-20	USE OF EXTERNAL INFORMATION SYSTEMS
AC-21	INFORMATION SHARING
AC-23	DATA MINING PROTECTION
AC-3	ACCESS ENFORCEMENT
AC-4	INFORMATION FLOW ENFORCEMENT
AC-5	SEPARATION OF DUTIES
AC-6	LEAST PRIVILEGE
AC-7	UNSUCCESSFUL LOGON ATTEMPTS
AC-8	SYSTEM USE NOTIFICATION
CA-2	SECURITY ASSESSMENTS
CA-3	SYSTEM INTERCONNECTIONS
CA-7	CONTINUOUS MONITORING
CA-8	PENETRATION TESTING
CM-10	SOFTWARE USAGE RESTRICTIONS
CM-11	USER-INSTALLED SOFTWARE
CM-12	INFORMATION LOCATION
CM-2	BASELINE CONFIGURATION
CM-3	CONFIGURATION CHANGE CONTROL
CM-5	ACCESS RESTRICTIONS FOR CHANGE
CM-6	CONFIGURATION SETTINGS
CM-7	LEAST FUNCTIONALITY
CM-8	INFORMATION SYSTEM COMPONENT INVENTORY
CP-10	INFORMATION SYSTEM RECOVERY AND RECONSTITUTION
CP-2	CONTINGENCY PLAN
CP-6	ALTERNATE STORAGE SITE
CP-7	ALTERNATE PROCESSING SITE
CP-9	INFORMATION SYSTEM BACKUP
IA-11	RE-AUTHENTICATION
IA-12	IDENTITY PROOFING
IA-2	IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS)
IA-3	DEVICE IDENTIFICATION AND AUTHENTICATION
IA-4	IDENTIFIER MANAGEMENT
IA-5	AUTHENTICATOR MANAGEMENT
IA-6	AUTHENTICATOR FEEDBACK
IA-7	CRYPTOGRAPHIC MODULE AUTHENTICATION
IA-8	IDENTIFICATION AND AUTHENTICATION (NON-ORGANIZATIONAL USERS)
IA-9	SERVICE IDENTIFICATION AND AUTHENTICATION
MP-7	MEDIA USE
RA-10	THREAT HUNTING
RA-5	VULNERABILITY SCANNING
RA-9	CRITICALITY ANALYSIS
SA-10	DEVELOPER CONFIGURATION MANAGEMENT
SA-11	DEVELOPER SECURITY TESTING AND EVALUATION
SA-15	DEVELOPMENT PROCESS, STANDARDS, AND TOOLS
SA-16	DEVELOPER-PROVIDED TRAINING
SA-17	DEVELOPER SECURITY ARCHITECTURE AND DESIGN
SA-22	UNSUPPORTED SYSTEM COMPONENTS
SA-3	SYSTEM DEVELOPMENT LIFE CYCLE
SA-4	ACQUISITION PROCESS
SA-8	SECURITY ENGINEERING PRINCIPLES
SA-9	EXTERNAL INFORMATION SYSTEM SERVICES
SC-10	NETWORK DISCONNECT
SC-12	CRYPTOGRAPHIC KEY ESTABLISHMENT AND MANAGEMENT
SC-13	CRYPTOGRAPHIC PROTECTION
SC-17	PUBLIC KEY INFRASTRUCTURE CERTIFICATES
SC-18	MOBILE CODE
SC-2	APPLICATION PARTITIONING
SC-20	SECURE NAME / ADDRESS RESOLUTION SERVICE (AUTHORITATIVE SOURCE)
SC-21	SECURE NAME / ADDRESS RESOLUTION SERVICE (RECURSIVE OR CACHING RESOLVER)
SC-22	ARCHITECTURE AND PROVISIONING FOR NAME / ADDRESS RESOLUTION SERVICE
SC-23	SESSION AUTHENTICITY
SC-26	HONEYPOTS
SC-28	PROTECTION OF INFORMATION AT REST
SC-29	HETEROGENEITY
SC-3	SECURITY FUNCTION ISOLATION
SC-30	CONCEALMENT AND MISDIRECTION
SC-31	COVERT CHANNEL ANALYSIS
SC-34	NON-MODIFIABLE EXECUTABLE PROGRAMS
SC-35	HONEYCLIENTS
SC-36	DISTRIBUTED PROCESSING AND STORAGE
SC-37	OUT-OF-BAND CHANNELS
SC-38	OPERATIONS SECURITY
SC-39	PROCESS ISOLATION
SC-4	INFORMATION IN SHARED RESOURCES
SC-41	PORT AND I/O DEVICE ACCESS
SC-43	USAGE RESTRICTIONS
SC-44	DETONATION CHAMBERS
SC-46	CROSS DOMAIN POLICY ENFORCEMENT
SC-7	BOUNDARY PROTECTION
SC-8	TRANSMISSION CONFIDENTIALITY AND INTEGRITY
SI-10	INFORMATION INPUT VALIDATION
SI-12	INFORMATION HANDLING AND RETENTION
SI-15	INFORMATION OUTPUT FILTERING
SI-16	MEMORY PROTECTION
SI-2	FLAW REMEDIATION
SI-23	INFORMATION FRAGMENTATIO
SI-3	MALICIOUS CODE PROTECTION
SI-4	INFORMATION SYSTEM MONITORING
SI-5	SECURITY ALERTS, ADVISORIES, AND DIRECTIVES
SI-7	SOFTWARE, FIRMWARE, AND INFORMATION INTEGRITY
SI-8	SPAM PROTECTION
SR-11	COMPONENT AUTHENTICITY
SR-4	PROVENANCE
SR-5	ACQUISITION STRATEGIES, TOOLS, AND METHODS
SR-6	SUPPLIER ASSESSMENTS AND REVIEWS
AC-1	POLICY AND PROCEDURES
AC-22	PUBLICLY ACCESSIBLE CONTENT
AT-1	POLICY AND PROCEDURES
AT-2	LITERACY TRAINING AND AWARENESS
AT-3	ROLE-BASED TRAINING
AU-1	POLICY AND PROCEDURES
AU-11	AUDIT RECORD RETENTION
AU-12	AUDIT RECORD GENERATION
AU-2	EVENT LOGGING
AU-3	CONTENT OF AUDIT RECORDS
AU-4	AUDIT LOG STORAGE CAPACITY
AU-6	AUDIT RECORD REVIEW, ANALYSIS, AND REPORTING
AU-7	AUDIT RECORD REDUCTION AND REPORT GENERATION
AU-9	PROTECTION OF AUDIT INFORMATION
CA-5	PLAN OF ACTION AND MILESTONES
CA-9	INTERNAL SYSTEM CONNECTION
CM-1	POLICY AND PROCEDURES
CM-9	CONFIGURATION MANAGEMENT PLAN
CP-4	CONTINGENCY PLAN TESTING
IR-4	INCIDENT HANDLING
MA-3	MAINTENANCE TOOLS
MA-4	NONLOCAL MAINTENANCE
MP-2	MEDIA ACCESS
PL-8	SECURITY AND PRIVACY ARCHITECTURES
PM-13	SECURITY AND PRIVACY WORKFORCE
PM-5	SYSTEM INVENTORY
PM-7	ENTERPRISE ARCHITECTURE
RA-1	POLICY AND PROCEDURES
RA-2	SECURITY CATEGORIZATION
RA-7	RISK RESPONSE
SR-12	COMPONENT DISPOSAL
\.


                                                                                                                                                         4457.dat                                                                                            0000600 0004000 0002000 00000020272 14362250176 0014266 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        CA-7	12.10.5 
A.13.2.2	1.1.2
A.13.2.2	1.1.3
AC-1	12.3
AC-1	12.3.10
AC-1	12.3.8
AC-1	12.3.9
AC-1	2.1
AC-1	2.3
AC-1	6.4.2
AC-1	7.1
AC-1	7.1.4
AC-1	7.2
AC-1	8.1
AC-1	8.1.5
AC-1	8.2
AC-1	8.2.2
AC-1	8.3
AC-1	8.5
AC-1	8.5.1
AC-1	8.6
AC-1	8.7
AC-1	9.3
AC-10	1.1
AC-10	1.2
AC-10	1.3
AC-10	10.8
AC-10	11.3
AC-10	2.2
AC-10	6.2
AC-11	8.2
AC-11	8.3
AC-12	8.2
AC-12	8.3
AC-14	6.4.2
AC-14	7.1
AC-14	7.2
AC-14	8.2
AC-14	8.3
AC-14	8.7
AC-14	9.3
AC-16	6.4.2
AC-16	7.1
AC-16	7.1.4
AC-16	7.2
AC-16	8.1
AC-16	8.2.2
AC-16	8.7
AC-16	9.3
AC-17	1
AC-17	2
AC-17	12.3.10
AC-17	12.3.8
AC-17	12.3.9
AC-17	2.3
AC-17	8.1.5
AC-17	8.3
AC-17	8.5.1
AC-18	1
AC-18	2
AC-19	12.3.10
AC-19	12.3.8
AC-19	12.3.9
AC-19	2.3
AC-19	7.1.4
AC-19	8.1
AC-19	8.1.5
AC-19	8.2.2
AC-19	8.3
AC-19	8.5.1
AC-2	10.6.1
AC-2	10.6.2
AC-2	11.4
AC-2	12.3
AC-2	2.1
AC-2	6.4.2
AC-2	7.1
AC-2	7.1.4
AC-2	7.2
AC-2	8.1
AC-2	8.2
AC-2	8.2.2
AC-2	8.5
AC-2	8.6
AC-2	8.7
AC-2	9.1.1
AC-2	9.3
AC-20	1.1.1
AC-20	1.1.2
AC-20	1.1.3
AC-20	12.3.10
AC-20	12.3.8
AC-20	12.3.9
AC-20	2.3
AC-20	2.4
AC-20	8.1.5
AC-20	8.3
AC-20	8.5.1
AC-24	6.4.2
AC-24	7.1
AC-24	7.1.4
AC-24	7.2
AC-24	8.1
AC-24	8.2.2
AC-24	8.7
AC-24	9.3
AC-25	10.9
AC-25	11.2
AC-25	11.3
AC-25	11.4
AC-25	12.10.1
AC-3	2.2
AC-3	6.4.2
AC-3	7.1
AC-3	7.1.4
AC-3	7.2
AC-3	8.1
AC-3	8.2.2
AC-3	8.7
AC-3	9.3
AC-4	1
AC-4	2
AC-4	1.1
AC-4	1.1.1
AC-4	1.1.2
AC-4	1.1.3
AC-4	1.2
AC-4	1.3
AC-4	10.6
AC-4	10.8
AC-4	11.3
AC-4	2.2
AC-4	6.2
AC-5	10.6
AC-5	6.4.2
AC-5	7.1
AC-5	7.2
AC-5	8.7
AC-5	9.3
AC-6	10.6
AC-6	6.4.2
AC-6	7.1
AC-6	7.2
AC-6	8.7
AC-6	9.3
AC-7	8.2
AC-7	8.3
AC-8	8.2
AC-8	8.3
AC-9	8.2
AC-9	8.3
AT-2	12.4
AT-2	12.6
AT-2	6.7
AT-2	7.3
AT-2	8.4
AT-2	9.9.3
AT-3	1.1.5
AT-3	12.4
AT-3	12.5
AT-3	12.6
AT-3	7.1
AT-3	7.2
AT-3	7.3
AU-12	10.1
AU-12	10.6.1
AU-12	10.6.2
AU-12	11.1
AU-12	11.4
AU-12	11.5
AU-12	12.10.5 
AU-12	9.1.1
AU-13	9.1.1
AU-6	10.1
AU-6	10.6
AU-6	10.6.3
AU-6	10.8
AU-6	12.1
AU-6	12.10.5
AU-6	12.5.2
AU-7	12.5.2
CA-2	10.6.1
CA-2	10.8
CA-2	10.9
CA-2	11.2
CA-2	11.3
CA-2	11.4
CA-2	12.1
CA-2	12.10.1
CA-2	12.10.6
CA-2	12.11
CA-2	12.2
CA-2	12.5.2
CA-2	6.1
CA-2	9.9.3
CA-3	1.1.1
CA-3	1.1.2
CA-3	1.1.3
CA-7	10.1
CA-7	10.6
CA-7	10.6.1
CA-7	10.6.2
CA-7	10.6.3
CA-7	10.8
CA-7	10.9
CA-7	11.1
CA-7	11.2
CA-7	11.3
CA-7	11.4
CA-7	11.5
CA-7	12.1
CA-7	12.10.1
CA-7	12.10.5
CA-7	12.10.6
CA-7	12.11
CA-7	12.2
CA-7	12.5.2
CA-7	6.1
CA-7	6.2
CA-7	8.1.5
CA-7	9.1.1
CA-7	9.9.3
CA-8	11.2
CA-8	11.3
CA-8	12.2
CA-8	6.1
CA-9	1.1.2
CA-9	1.1.3
CM-10	9.1.1
CM-11	9.1.1
CM-2	1.1.1
CM-2	1.1.2
CM-2	1.1.3
CM-2	1.2
CM-2	2.2
CM-2	6.4.1
CM-2	6.4.2
CM-3	1.2
CM-3	10.1
CM-3	10.6.1
CM-3	10.6.2
CM-3	11.1
CM-3	11.4
CM-3	11.5
CM-3	12.10.5
CM-3	2.2
CM-4	1.2
CM-4	2.2
CM-5	1.2
CM-5	2.2
CM-6	1.2
CM-6	2.2
CM-7	1.2
CM-7	2.2
CM-7	7.1
CM-7	7.2
CM-7	9.3
CM-8	10.1
CM-8	10.6.1
CM-8	11.1
CM-8	11.4
CM-8	11.5
CM-8	12.10.5
CM-8	2.4
CM-8	9.5
CM-8	9.6
CM-8	9.7
CM-8	9.8
CM-8	9.9
CM-9	1.2
CM-9	2.2
CP-10	12.1
CP-10	12.10.6
CP-12	11.1.2
CP-12	12.1
CP-12	12.5.3
CP-13	11.1.2
CP-13	12.1
CP-13	12.5.3
CP-3	12.1
CP-4	12.1
CP-4	12.10.1
CP-4	12.10.2
CP-4	9.5.1
CP-6	12.10.2
CP-6	9.5.1
CP-7	11.1.2
CP-7	12.1
CP-7	12.5.3
CP-8	1
CP-8	2
CP-9	12.10.1
CP-9	12.10.2
CP-9	9.5.1
IA-1	12.3
IA-1	2.1
IA-1	8.1
IA-1	8.2
IA-1	8.3
IA-1	8.5
IA-1	8.6
IA-10	12.3
IA-10	2.1
IA-10	8.1
IA-10	8.2
IA-10	8.3
IA-10	8.5
IA-10	8.6
IA-11	12.3
IA-11	2.1
IA-11	8.1
IA-11	8.2
IA-11	8.3
IA-11	8.5
IA-11	8.6
IA-2	12.3
IA-2	2.1
IA-2	7.1.4
IA-2	8.1
IA-2	8.2
IA-2	8.2.2
IA-2	8.3
IA-2	8.5
IA-2	8.6
IA-3	12.3
IA-3	2.1
IA-3	8.1
IA-3	8.2
IA-3	8.3
IA-3	8.5
IA-3	8.6
IA-4	12.3
IA-4	2.1
IA-4	7.1.4
IA-4	8.1
IA-4	8.2
IA-4	8.2.2
IA-4	8.3
IA-4	8.5
IA-4	8.6
IA-5	12.3
IA-5	2.1
IA-5	7.1.4
IA-5	8.1
IA-5	8.2
IA-5	8.2.2
IA-5	8.3
IA-5	8.5
IA-5	8.6
IA-6	12.3
IA-6	2.1
IA-6	8.1
IA-6	8.2
IA-6	8.5
IA-6	8.6
IA-7	12.3
IA-7	2.1
IA-7	8.1
IA-7	8.2
IA-7	8.5
IA-7	8.6
IA-8	12.3
IA-8	2.1
IA-8	7.1.4
IA-8	8.1
IA-8	8.2
IA-8	8.2.2
IA-8	8.3
IA-8	8.5
IA-8	8.6
IA-9	12.3
IA-9	2.1
IA-9	8.1
IA-9	8.2
IA-9	8.3
IA-9	8.5
IA-9	8.6
IR-2	12.4
IR-2	12.5
IR-3	12.1
IR-3	12.10.2
IR-4	10.1
IR-4	10.6
IR-4	10.6.3
IR-4	12.1
IR-4	12.10.1
IR-4	12.10.5
IR-4	12.10.6
IR-4	12.5.2
IR-5	10.1
IR-5	10.6
IR-5	10.6.3
IR-5	12.10.5
IR-5	12.5.2
IR-6	10.8
IR-6	12.1
IR-7	11.1.2
IR-7	12.1
IR-7	12.5.3
IR-8	10.1
IR-8	10.6
IR-8	10.8
IR-8	11.1.2
IR-8	12.1
IR-8	12.10.1
IR-8	12.10.5
IR-8	12.10.6
IR-8	12.11
IR-8	12.5.2
IR-8	12.5.3
IR-8 	12.1
IR-9	11.1.2
IR-9	12.1
IR-9	12.5.3
MP-6	2.4
MP-6	3.1
MP-6	9.5
MP-6	9.6
MP-6	9.7
MP-6	9.8
MP-6	9.9
MP-8	8.2.1
PE-16	2.4
PE-16	9.5
PE-16	9.6
PE-16	9.7
PE-16	9.8
PE-16	9.9
PE-17	11.1.2
PE-17	12.1
PE-17	12.5.3
PE-19	10.6
PE-2	7.1.4
PE-2	8.1
PE-2	8.2.2
PE-20	10.1
PE-20	10.6.1
PE-20	11.1
PE-20	11.4
PE-20	11.5
PE-20	12.10.5
PE-20	9.1.1
PE-3	10.1
PE-3	10.6.1
PE-3	10.9
PE-3	11.1
PE-3	11.2
PE-3	11.3
PE-3	11.4
PE-3	11.5
PE-3	12.1
PE-3	12.10.5
PE-3	9.1.1
PE-6	10.1
PE-6	10.6.1
PE-6	10.6.3
PE-6	11.1
PE-6	11.4
PE-6	11.5
PE-6	12.1
PE-6	12.10.5
PE-6	12.5.2
PE-6	9.1.1
PL-2	10.8
PL-2	12.10.6
PL-2	12.11
PL-8	1.1.2
PL-8	1.1.3
PL-8	6.3
PL-8	6.4
PL-8	6.5
PL-8	6.6
PL-8	6.7
PM-11	12.2
PM-11	12.4
PM-11	12.5
PM-11	12.8
PM-11	12.9
PM-11	6.1
PM-12	12.2
PM-13	1.1.5
PM-13	12.4
PM-13	12.5
PM-13	12.6
PM-13	6.7
PM-13	7.1
PM-13	7.2
PM-13	7.3
PM-13	8.4
PM-13	9.9.3
PM-14	10.6.1
PM-14	10.9
PM-14	11.2
PM-14	11.3
PM-14	11.4
PM-14	12.1
PM-14	12.10.1
PM-14	12.10.2
PM-14	12.10.6
PM-14	12.5.2
PM-14	9.9.3
PM-15	6.1
PM-15	6.2
PM-16	12.2
PM-16	6.1
PM-4	12.10.1
PM-6	10.8
PM-6	12.10.6
PM-6	12.11
PM-8	12.2
PM-9	12.10.1
PM-9	12.2
PM-9	12.8
PM-9	12.9
PM-9	6.1
PS-1	12.7
PS-1	8.1.3
PS-1	9.3
PS-2	12.7
PS-2	8.1.3
PS-2	9.3
PS-3	10.6
PS-3	12.7
PS-3	7.1.4
PS-3	8.1
PS-3	8.1.3
PS-3	8.2.2
PS-3	9.3
PS-4	12.7
PS-4	8.1.3
PS-4	9.3
PS-5	12.7
PS-5	8.1.3
PS-5	9.3
PS-6	10.6
PS-6	12.7
PS-6	8.1.3
PS-6	9.3
PS-7	10.6
PS-7	12.4
PS-7	12.5
PS-7	12.7
PS-7	12.8
PS-7	12.8.2
PS-7	12.9
PS-7	8.1.3
PS-7	8.1.5
PS-7	9.3
PS-8	12.7
PS-8	8.1.3
PS-8	9.3
RA-2	12.2
RA-2	12.8
RA-2	6.1
RA-2	9.6.1
RA-3	10.6.3
RA-3	11.2
RA-3	11.3
RA-3	12.1
RA-3	12.2
RA-3	12.5.2
RA-3	12.8
RA-3	6.1
RA-3	6.2
RA-3	6.5
RA-5	10.6.3
RA-5	11.2
RA-5	11.3
RA-5	12.1
RA-5	12.10.6
RA-5	12.2
RA-5	12.5.2
RA-5	6.1
RA-5	6.2
RA-5	6.5
SA-10	1.2
SA-10	2.2
SA-10	6.3
SA-10	6.4
SA-10	6.5
SA-10	6.6
SA-10	6.7
SA-10	9.9.2
SA-11	11.2
SA-11	11.3
SA-11	12.2
SA-11	12.8
SA-11	12.9
SA-11	6.1
SA-11	6.3
SA-11	6.4
SA-11	6.5
SA-11	6.6
SA-11	6.7
SA-12	12.2
SA-12	12.8
SA-12	12.9
SA-12	6.3
SA-12	6.4
SA-12	6.5
SA-12	6.6
SA-12	6.7
SA-14	12.2
SA-14	12.8
SA-14	6.1
SA-14	9.6.1
SA-15	12.8
SA-15	6.3
SA-15	6.4
SA-15	6.5
SA-15	6.6
SA-15	6.7
SA-16	12.8.2
SA-16	12.9
SA-17	6.3
SA-17	6.4
SA-17	6.5
SA-17	6.6
SA-17	6.7
SA-18	10.9
SA-18	11.2
SA-18	11.3
SA-18	11.4
SA-18	12.10.1
SA-21	12.7
SA-21	8.1.3
SA-21	9.3
SA-3	6.3
SA-3	6.4
SA-3	6.5
SA-3	6.6
SA-3	6.7
SA-4	10.6
SA-4	6.3
SA-4	6.4
SA-4	6.5
SA-4	6.6
SA-4	6.7
SA-4	8.1.5
SA-5	11.2
SA-5	11.3
SA-5	12.2
SA-5	6.1
SA-8	6.3
SA-8	6.4
SA-8	6.5
SA-8	6.6
SA-8	6.7
SA-9	1.1.1
SA-9	1.1.2
SA-9	1.1.3
SA-9	10.6
SA-9	12.2
SA-9	12.8
SA-9	12.8.2
SA-9	12.9
SA-9	2.4
SA-9	8.1.5
SC-11	8.2.1
SC-12	8.2.1
SC-13	10.6
SC-16	11.5
SC-18	5
SC-19	1
SC-19	2
SC-20	1
SC-20	2
SC-21	1
SC-21	2
SC-22	1
SC-22	2
SC-23	1
SC-23	2
SC-24	1
SC-24	2
SC-25	1
SC-25	2
SC-28	8.2.1
SC-29	1
SC-29	2
SC-31	10.6
SC-32	1
SC-32	2
SC-36	1
SC-36	2
SC-37	1
SC-37	2
SC-38	1
SC-38	2
SC-39	1
SC-39	2
SC-40	1
SC-40	2
SC-41	1
SC-41	2
SC-43	1
SC-43	2
SC-44	5
SC-5	10.6.1
SC-5	10.6.2
SC-5	11.4
SC-6	12.2
SC-6	9.6.1
SC-7	1
SC-7	2
SC-7	1.1
SC-7	1.2
SC-7	1.3
SC-7	10.6
SC-7	10.6.1
SC-7	10.6.2
SC-7	10.8
SC-7	11.3
SC-7	11.4
SC-7	2.2
SC-7	6.2
SC-8	10.6
SC-8	8.2.1
SI-4	10.6.3
SI-4	12.5.2
SI-12	6.3
SI-12	6.4
SI-12	6.5
SI-12	6.6
SI-12	6.7
SI-13	6.3
SI-13	6.4
SI-13	6.5
SI-13	6.6
SI-13	6.7
SI-14	6.3
SI-14	6.4
SI-14	6.5
SI-14	6.6
SI-14	6.7
SI-16	6.3
SI-16	6.4
SI-16	6.5
SI-16	6.6
SI-16	6.7
SI-17	6.3
SI-17	6.4
SI-17	6.5
SI-17	6.6
SI-17	6.7
SI-2	11.2
SI-2	11.3
SI-2	12.2
SI-2	6.1
SI-2	6.2
SI-2	6.5
SI-3	5
SI-3	10.6.1
SI-3	10.9
SI-3	11.2
SI-3	11.3
SI-3	12.1
SI-4	5
SI-4	1.1.1
SI-4	1.1.2
SI-4	1.1.3
SI-4	10.1
SI-4	10.6
SI-4	10.6.1
SI-4	10.6.2
SI-4	10.9
SI-4	11.1
SI-4	11.2
SI-4	11.3
SI-4	11.4
SI-4	11.5
SI-4	12.1
SI-4	12.10.1
SI-4	12.10.5
SI-4	12.10.6
SI-4	12.2
SI-4	6.1
SI-4	8.1.5
SI-5	11.2
SI-5	11.3
SI-5	12.2
SI-5	6.1
SI-5	6.2
SI-7	11.5
SI-7	9.9.2
SI-8	5
AU-6	11.5.1
AU-7	11.5.1
CA-7	11.5.1
IR-4	11.5.1
IR-5	11.5.1
IR-8	11.5.1
PE-6	11.5.1
RA-3	11.5.1
RA-5	11.5.1
SI-4	11.5.1
CP-2	10.6.3
CP-2	10.8
CP-2	11.1.2
CP-2	12.1
CP-2	12.10.1
CP-2	12.10.6
CP-2	12.11
CP-2	12.2
CP-2	12.4
CP-2	12.5
CP-2	12.5.2
CP-2	12.5.3
CP-2	12.8
CP-2	12.9
CP-2	9.6.1
CP-2	11.5.1
\.


                                                                                                                                                                                                                                                                                                                                      4456.dat                                                                                            0000600 0004000 0002000 00000023477 14362250176 0014277 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        8.2	Assign a unique ID to each person with computer access
8.3	Assign a unique ID to each person with computer access
2.4	Do not use vendor-supplied defaults for system passwords and other security parameters
9.5	Restrict physical access to cardholder data
9.6	Restrict physical access to cardholder data
9.7	Restrict physical access to cardholder data
9.8	Restrict physical access to cardholder data
9.9	Restrict access to cardholder data by business need to know
1.1.1	Install and maintain a firewall configuration to protect cardholder data
1.1.2	Install and maintain a firewall configuration to protect cardholder data
1.1.3	Install and maintain a firewall configuration to protect cardholder data
10.1	Track and monitor all access to network resources and cardholder data
12.10.5	Maintain a policy that addresses information security for all personnel
10.6	Track and monitor all access to network resources and cardholder data
1.2	Install and maintain a firewall configuration to protect cardholder data
2.2	Do not use vendor-supplied defaults for system passwords and other security parameters
7.1	Restrict access to cardholder data by business need to know
7.2	Restrict access to cardholder data by business need to know
9.3	Restrict access to cardholder data by business need to know
12.5.2	Maintain a policy that addresses information security for all personnel
6.1	Develop and maintain secure systems and applications
11.2	Regularly test security systems and processes
11.3	Regularly test security systems and processes
12.2	Maintain a policy that addresses information security for all personnel
12.10.1	Maintain a policy that addresses information security for all personnel
6.2	Develop and maintain secure systems and applications
6.5	Develop and maintain secure systems and applications
10.6.3	Track and monitor all access to network resources and cardholder data
5	Use and regularly update anti-virus software or programs
12.1	Maintain a policy that addresses information security for all personnel
1.1.5	Install and maintain a firewall configuration to protect cardholder data
7.3	Restrict access to cardholder data by business need to know
12.4	Maintain a policy that addresses information security for all personnel
12.6	Maintain a policy that addresses information security for all personnel
8.1.3	Assign a unique ID to each person with computer access
12.7	Maintain a policy that addresses information security for all personnel
9.1.1	Restrict access to cardholder data by business need to know
10.6.1	Track and monitor all access to network resources and cardholder data
10.6.2	Track and monitor all access to network resources and cardholder data
11.4	Regularly test security systems and processes
1	Install and maintain a firewall configuration to protect cardholder data
2	Do not use vendor-supplied defaults for system passwords and other security parameters
1.1	Install and maintain a firewall configuration to protect cardholder data
1.3	Install and maintain a firewall configuration to protect cardholder data
10.8	Track and monitor all access to network resources and cardholder data
9.5.1	Restrict access to cardholder data by business need to know
12.10.2	Maintain a policy that addresses information security for all personnel
12.10.6	Maintain a policy that addresses information security for all personnel
6.4.2	Develop and maintain secure systems and applications
8.7	Assign a unique ID to each person with computer access
9.6.1	Restrict access to cardholder data by business need to know
8.2.1	Assign a unique ID to each person with computer access
2.1	Do not use vendor-supplied defaults for system passwords and other security parameters
8.1	Assign a unique ID to each person with computer access
8.5	Assign a unique ID to each person with computer access
8.6	Assign a unique ID to each person with computer access
12.3	Maintain a policy that addresses information security for all personnel
7.1.4	Restrict access to cardholder data by business need to know
8.2.2	Assign a unique ID to each person with computer access
6.7	Develop and maintain secure systems and applications
8.4	Assign a unique ID to each person with computer access
9.9.3	Restrict access to cardholder data by business need to know
12.8.2	Maintain a policy that addresses information security for all personnel
12.9	Maintain a policy that addresses information security for all personnel
6.4.1	Develop and maintain secure systems and applications
6.3	Develop and maintain secure systems and applications
6.4	Develop and maintain secure systems and applications
6.6	Develop and maintain secure systems and applications
12.5	Maintain a policy that addresses information security for all personnel
12.8	Maintain a policy that addresses information security for all personnel
11.1.2	Regularly test security systems and processes
12.5.3	Maintain a policy that addresses information security for all personnel
9.9.1	Restrict access to cardholder data by business need to know
11.1.1	Regularly test security systems and processes
11.1	Regularly test security systems and processes
5.1	Use and regularly update anti-virus software or programs
5.1.1	Use and regularly update anti-virus software or programs
5.2	Use and regularly update anti-virus software or programs
1.4	Install and maintain a firewall configuration to protect cardholder data
1.1.6	Install and maintain a firewall configuration to protect cardholder data
1.2.3	Install and maintain a firewall configuration to protect cardholder data
2.2.2	Do not use vendor-supplied defaults for system passwords and other security parameters
2.1.1	Do not use vendor-supplied defaults for system passwords and other security parameters
4.1.1	Encrypt transmission of cardholder data across open, public networks
10.5.3	Track and monitor all access to network resources and cardholder data
1.1.4	Install and maintain a firewall configuration to protect cardholder data
1.3.2	Install and maintain a firewall configuration to protect cardholder data
1.3.3	Install and maintain a firewall configuration to protect cardholder data
1.3.4	Install and maintain a firewall configuration to protect cardholder data
1.3.5	Install and maintain a firewall configuration to protect cardholder data
12.6.1	Maintain a policy that addresses information security for all personnel
12.6.2	Maintain a policy that addresses information security for all personnel
12.10.4	Maintain a policy that addresses information security for all personnel
6.3.2	Develop and maintain secure systems and applications
6.5.1	Develop and maintain secure systems and applications
6.5.2	Develop and maintain secure systems and applications
6.5.3	Develop and maintain secure systems and applications
6.5.4	Develop and maintain secure systems and applications
6.5.5	Develop and maintain secure systems and applications
6.5.6	Develop and maintain secure systems and applications
6.5.7	Develop and maintain secure systems and applications
6.5.8	Develop and maintain secure systems and applications
6.5.9	Develop and maintain secure systems and applications
6.5.10	Develop and maintain secure systems and applications
12.10.3	Maintain a policy that addresses information security for all personnel
11.3.1	Regularly test security systems and processes
11.3.2	Regularly test security systems and processes
11.5	Regularly test security systems and processes
4.1	Encrypt transmission of cardholder data across open, public networks
3.4	Protect stored cardholder data
3.4.1 	Protect stored cardholder data
2.2.1	Do not use vendor-supplied defaults for system passwords and other security parameters
10.2.1	Track and monitor all access to network resources and cardholder data
7.1.1	Restrict access to cardholder data by business need to know
7.1.2	Restrict access to cardholder data by business need to know
7.1.3	Restrict access to cardholder data by business need to know
1.2.2	Install and maintain a firewall configuration to protect cardholder data
8.1.8	Assign a unique ID to each person with computer access
1.3.1	Install and maintain a firewall configuration to protect cardholder data
1.2.1	Install and maintain a firewall configuration to protect cardholder data
2.2.5	Do not use vendor-supplied defaults for system passwords and other security parameters
8.1.1	Assign a unique ID to each person with computer access
8.1.4	Assign a unique ID to each person with computer access
2.3	Do not use vendor-supplied defaults for system passwords and other security parameters
8.3.2	Assign a unique ID to each person with computer access
8.3.1	Assign a unique ID to each person with computer access
11.2.1	Regularly test security systems and processes
10.7	Track and monitor all access to network resources and cardholder data
10.2	Track and monitor all access to network resources and cardholder data
10.3	Track and monitor all access to network resources and cardholder data
10.4	Track and monitor all access to network resources and cardholder data
10.2.2	Track and monitor all access to network resources and cardholder data
10.2.4	Track and monitor all access to network resources and cardholder data
10.2.5	Track and monitor all access to network resources and cardholder data
10.5.4	Track and monitor all access to network resources and cardholder data
12.10.5 	Maintain a policy that addresses information security for all personnel
12.3.10	Maintain a policy that addresses information security for all personnel
12.3.8	Maintain a policy that addresses information security for all personnel
12.3.9	Maintain a policy that addresses information security for all personnel
8.1.5	Assign a unique ID to each person with computer access
8.5.1	Assign a unique ID to each person with computer access
10.9	Track and monitor all access to network resources and cardholder data
12.11	Maintain a policy that addresses information security for all personnel
3,1	Protect stored cardholder data
9.9.2	Restrict access to cardholder data by business need to know
3.1	Protect stored cardholder data
11.5.1	Regularly test security systems and processes
\.


                                                                                                                                                                                                 restore.sql                                                                                         0000600 0004000 0002000 00000062735 14362250176 0015407 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        --
-- NOTE:
--
-- File paths need to be edited. Search for $$PATH$$ and
-- replace it with the path to the directory containing
-- the extracted data files.
--
--
-- PostgreSQL database dump
--

-- Dumped from database version 14.4
-- Dumped by pg_dump version 14.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

DROP DATABASE vsocmitreintegrationdatabase;
--
-- Name: vsocmitreintegrationdatabase; Type: DATABASE; Schema: -; Owner: mirmaster
--

CREATE DATABASE vsocmitreintegrationdatabase WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'en_US.UTF-8';


ALTER DATABASE vsocmitreintegrationdatabase OWNER TO mirmaster;

\connect vsocmitreintegrationdatabase

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: aws_commons; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS aws_commons WITH SCHEMA public;


--
-- Name: EXTENSION aws_commons; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION aws_commons IS 'Common data types across AWS services';


--
-- Name: aws_s3; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS aws_s3 WITH SCHEMA public;


--
-- Name: EXTENSION aws_s3; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION aws_s3 IS 'AWS S3 extension for importing data from S3';


--
-- Name: updater_loop(); Type: FUNCTION; Schema: public; Owner: mirmaster
--

CREATE FUNCTION public.updater_loop() RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
  i RECORD;
BEGIN
  --FOR i IN (SELECT ROW_NUMBER() OVER(ORDER BY (SELECT 0)) RowId,* FROM aws_base)
  FOR i IN (
    SELECT ROW_NUMBER() OVER(ORDER BY (SELECT 0)) AS RowId,
    SUBSTRING(ttp_description,1,LENGTH(ttp_description)-1) AS ttp_description,
    ttp_id
    FROM mitre_ttp_base
    )
  LOOP
    UPDATE mitre_ttp_base
    SET
        ttp_description = i.ttp_description,
        ttp_description_eng = i.ttp_description
    WHERE ttp_id = i.ttp_id;
  END LOOP;
END;
$$;


ALTER FUNCTION public.updater_loop() OWNER TO mirmaster;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: aws_base; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.aws_base (
    event_rule character varying(110) NOT NULL,
    service character varying(25) NOT NULL,
    m_type character varying(10),
    m_details_esp character varying(350) NOT NULL,
    m_details_eng character varying(350) NOT NULL
);


ALTER TABLE public.aws_base OWNER TO mirmaster;

--
-- Name: c5_base; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.c5_base (
    c5_id character varying(10) NOT NULL,
    title character varying(170)
);


ALTER TABLE public.c5_base OWNER TO mirmaster;

--
-- Name: cis_base; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.cis_base (
    cis_id character varying(10) NOT NULL,
    title character varying(170)
);


ALTER TABLE public.cis_base OWNER TO mirmaster;

--
-- Name: cis_nist_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.cis_nist_dir (
    cis_id character varying(10) NOT NULL,
    nist_id character varying(10) NOT NULL
);


ALTER TABLE public.cis_nist_dir OWNER TO mirmaster;

--
-- Name: cis_pci_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.cis_pci_dir (
    cis_id character varying(10) NOT NULL,
    pci_id character varying(10) NOT NULL
);


ALTER TABLE public.cis_pci_dir OWNER TO mirmaster;

--
-- Name: ens_base; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.ens_base (
    ens_id character varying(10) NOT NULL,
    title character varying(80)
);


ALTER TABLE public.ens_base OWNER TO mirmaster;

--
-- Name: mitre_aws_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.mitre_aws_dir (
    ttp_id character varying(50) NOT NULL,
    service character varying(50) NOT NULL,
    event_rule character varying(150) NOT NULL
);


ALTER TABLE public.mitre_aws_dir OWNER TO mirmaster;

--
-- Name: mitre_ttp_base; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.mitre_ttp_base (
    ttp_id character varying(20) NOT NULL,
    url character varying(60),
    mitigation_basic character varying(150),
    ttp_esp character varying(80),
    ttp_eng character varying(80),
    ttp_description_esp character varying(200),
    ttp_description_eng character varying(200)
);


ALTER TABLE public.mitre_ttp_base OWNER TO mirmaster;

--
-- Name: mitre_aws_view; Type: VIEW; Schema: public; Owner: mirmaster
--

CREATE VIEW public.mitre_aws_view AS
 SELECT mb_ad.ttp_id,
    mb_ad.ttp_esp,
    mb_ad.ttp_eng,
    aws_base.m_type,
    aws_base.service,
    aws_base.event_rule,
    aws_base.m_details_esp,
    aws_base.m_details_eng
   FROM (public.aws_base
     JOIN ( SELECT mitre_ttp_base.ttp_id,
            mitre_ttp_base.ttp_esp,
            mitre_ttp_base.ttp_eng,
            mitre_aws_dir.service,
            mitre_aws_dir.event_rule
           FROM (public.mitre_aws_dir
             JOIN public.mitre_ttp_base ON (((mitre_ttp_base.ttp_id)::text = (mitre_aws_dir.ttp_id)::text)))) mb_ad ON ((((aws_base.service)::text = (mb_ad.service)::text) AND ((aws_base.event_rule)::text = (mb_ad.event_rule)::text))));


ALTER TABLE public.mitre_aws_view OWNER TO mirmaster;

--
-- Name: mitre_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.mitre_dir (
    ta_id character varying(10) NOT NULL,
    ttp_id character varying(20) NOT NULL
);


ALTER TABLE public.mitre_dir OWNER TO mirmaster;

--
-- Name: mitre_ta_base; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.mitre_ta_base (
    ta_id character varying(10) NOT NULL,
    url character varying(60),
    ta_esp character varying(50),
    ta_eng character varying(50),
    ta_description_esp character varying(200),
    ta_description_eng character varying(200)
);


ALTER TABLE public.mitre_ta_base OWNER TO mirmaster;

--
-- Name: mitre_base_view; Type: VIEW; Schema: public; Owner: mirmaster
--

CREATE VIEW public.mitre_base_view AS
 SELECT mitre_ta.ta_id,
    mitre_ta.ta_esp,
    mitre_ta.ta_eng,
    mitre_ta.ttp_id,
    mitre_ttp_base.ttp_esp,
    mitre_ttp_base.ttp_eng,
    mitre_ttp_base.url,
    mitre_ttp_base.ttp_description_esp AS description_esp,
    mitre_ttp_base.ttp_description_eng AS description_eng,
    mitre_ttp_base.mitigation_basic
   FROM (public.mitre_ttp_base
     JOIN ( SELECT mitre_ta_base.ta_id,
            mitre_ta_base.ta_esp,
            mitre_ta_base.ta_eng,
            mitre_dir.ttp_id
           FROM (public.mitre_dir
             JOIN public.mitre_ta_base ON (((mitre_dir.ta_id)::text = (mitre_ta_base.ta_id)::text)))) mitre_ta ON (((mitre_ta.ttp_id)::text = (mitre_ttp_base.ttp_id)::text)))
  ORDER BY mitre_ta.ta_id, mitre_ta.ttp_id;


ALTER TABLE public.mitre_base_view OWNER TO mirmaster;

--
-- Name: mitre_c5_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.mitre_c5_dir (
    ttp_id character varying(50) NOT NULL,
    c5_id character varying(10) NOT NULL
);


ALTER TABLE public.mitre_c5_dir OWNER TO mirmaster;

--
-- Name: mitre_c5_view; Type: VIEW; Schema: public; Owner: mirmaster
--

CREATE VIEW public.mitre_c5_view AS
 SELECT mitre_c5_dir.ttp_id,
    c5_base.c5_id,
    c5_base.title
   FROM (public.c5_base
     JOIN public.mitre_c5_dir ON (((mitre_c5_dir.c5_id)::text = (c5_base.c5_id)::text)))
  ORDER BY mitre_c5_dir.ttp_id, c5_base.c5_id;


ALTER TABLE public.mitre_c5_view OWNER TO mirmaster;

--
-- Name: mitre_cis_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.mitre_cis_dir (
    ttp_id character varying(50) NOT NULL,
    cis_id character varying(10) NOT NULL
);


ALTER TABLE public.mitre_cis_dir OWNER TO mirmaster;

--
-- Name: mitre_cis_view; Type: VIEW; Schema: public; Owner: mirmaster
--

CREATE VIEW public.mitre_cis_view AS
 SELECT mitre_cis_dir.ttp_id,
    mitre_cis_dir.cis_id,
    cis_base.title
   FROM (public.mitre_cis_dir
     JOIN public.cis_base ON (((mitre_cis_dir.cis_id)::text = (cis_base.cis_id)::text)));


ALTER TABLE public.mitre_cis_view OWNER TO mirmaster;

--
-- Name: mitre_ens_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.mitre_ens_dir (
    ttp_id character varying(10) NOT NULL,
    ens_id character varying(10) NOT NULL
);


ALTER TABLE public.mitre_ens_dir OWNER TO mirmaster;

--
-- Name: mitre_ens_view; Type: VIEW; Schema: public; Owner: mirmaster
--

CREATE VIEW public.mitre_ens_view AS
 SELECT mitre_ens_dir.ttp_id,
    ens_base.ens_id,
    ens_base.title
   FROM (public.ens_base
     JOIN public.mitre_ens_dir ON (((mitre_ens_dir.ens_id)::text = (ens_base.ens_id)::text)))
  ORDER BY mitre_ens_dir.ttp_id, ens_base.ens_id;


ALTER TABLE public.mitre_ens_view OWNER TO mirmaster;

--
-- Name: mitre_nist_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.mitre_nist_dir (
    ttp_id character varying(50) NOT NULL,
    nist_id character varying(10) NOT NULL
);


ALTER TABLE public.mitre_nist_dir OWNER TO mirmaster;

--
-- Name: nist_base; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.nist_base (
    nist_id character varying(10) NOT NULL,
    title character varying(100)
);


ALTER TABLE public.nist_base OWNER TO mirmaster;

--
-- Name: mitre_nist_view; Type: VIEW; Schema: public; Owner: mirmaster
--

CREATE VIEW public.mitre_nist_view AS
 SELECT mitre_nist_dir.ttp_id,
    mitre_nist_dir.nist_id,
    nist_base.title
   FROM (public.mitre_nist_dir
     JOIN public.nist_base ON (((mitre_nist_dir.nist_id)::text = (nist_base.nist_id)::text)));


ALTER TABLE public.mitre_nist_view OWNER TO mirmaster;

--
-- Name: mitre_pci_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.mitre_pci_dir (
    ttp_id character varying(50) NOT NULL,
    pci_id character varying(10) NOT NULL
);


ALTER TABLE public.mitre_pci_dir OWNER TO mirmaster;

--
-- Name: pci_base; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.pci_base (
    pci_id character varying(10) NOT NULL,
    title character varying(150)
);


ALTER TABLE public.pci_base OWNER TO mirmaster;

--
-- Name: mitre_pci_view; Type: VIEW; Schema: public; Owner: mirmaster
--

CREATE VIEW public.mitre_pci_view AS
 SELECT mitre_pci_dir.ttp_id,
    mitre_pci_dir.pci_id,
    pci_base.title
   FROM (public.mitre_pci_dir
     JOIN public.pci_base ON (((mitre_pci_dir.pci_id)::text = (pci_base.pci_id)::text)));


ALTER TABLE public.mitre_pci_view OWNER TO mirmaster;

--
-- Name: nist_pci_dir; Type: TABLE; Schema: public; Owner: mirmaster
--

CREATE TABLE public.nist_pci_dir (
    nist_id character varying(10) NOT NULL,
    pci_id character varying(10) NOT NULL
);


ALTER TABLE public.nist_pci_dir OWNER TO mirmaster;

--
-- Data for Name: aws_base; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.aws_base (event_rule, service, m_type, m_details_esp, m_details_eng) FROM stdin;
\.
COPY public.aws_base (event_rule, service, m_type, m_details_esp, m_details_eng) FROM '$$PATH$$/4440.dat';

--
-- Data for Name: c5_base; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.c5_base (c5_id, title) FROM stdin;
\.
COPY public.c5_base (c5_id, title) FROM '$$PATH$$/4441.dat';

--
-- Data for Name: cis_base; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.cis_base (cis_id, title) FROM stdin;
\.
COPY public.cis_base (cis_id, title) FROM '$$PATH$$/4442.dat';

--
-- Data for Name: cis_nist_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.cis_nist_dir (cis_id, nist_id) FROM stdin;
\.
COPY public.cis_nist_dir (cis_id, nist_id) FROM '$$PATH$$/4443.dat';

--
-- Data for Name: cis_pci_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.cis_pci_dir (cis_id, pci_id) FROM stdin;
\.
COPY public.cis_pci_dir (cis_id, pci_id) FROM '$$PATH$$/4444.dat';

--
-- Data for Name: ens_base; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.ens_base (ens_id, title) FROM stdin;
\.
COPY public.ens_base (ens_id, title) FROM '$$PATH$$/4445.dat';

--
-- Data for Name: mitre_aws_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.mitre_aws_dir (ttp_id, service, event_rule) FROM stdin;
\.
COPY public.mitre_aws_dir (ttp_id, service, event_rule) FROM '$$PATH$$/4446.dat';

--
-- Data for Name: mitre_c5_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.mitre_c5_dir (ttp_id, c5_id) FROM stdin;
\.
COPY public.mitre_c5_dir (ttp_id, c5_id) FROM '$$PATH$$/4450.dat';

--
-- Data for Name: mitre_cis_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.mitre_cis_dir (ttp_id, cis_id) FROM stdin;
\.
COPY public.mitre_cis_dir (ttp_id, cis_id) FROM '$$PATH$$/4451.dat';

--
-- Data for Name: mitre_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.mitre_dir (ta_id, ttp_id) FROM stdin;
\.
COPY public.mitre_dir (ta_id, ttp_id) FROM '$$PATH$$/4448.dat';

--
-- Data for Name: mitre_ens_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.mitre_ens_dir (ttp_id, ens_id) FROM stdin;
\.
COPY public.mitre_ens_dir (ttp_id, ens_id) FROM '$$PATH$$/4452.dat';

--
-- Data for Name: mitre_nist_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.mitre_nist_dir (ttp_id, nist_id) FROM stdin;
\.
COPY public.mitre_nist_dir (ttp_id, nist_id) FROM '$$PATH$$/4453.dat';

--
-- Data for Name: mitre_pci_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.mitre_pci_dir (ttp_id, pci_id) FROM stdin;
\.
COPY public.mitre_pci_dir (ttp_id, pci_id) FROM '$$PATH$$/4455.dat';

--
-- Data for Name: mitre_ta_base; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.mitre_ta_base (ta_id, url, ta_esp, ta_eng, ta_description_esp, ta_description_eng) FROM stdin;
\.
COPY public.mitre_ta_base (ta_id, url, ta_esp, ta_eng, ta_description_esp, ta_description_eng) FROM '$$PATH$$/4449.dat';

--
-- Data for Name: mitre_ttp_base; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.mitre_ttp_base (ttp_id, url, mitigation_basic, ttp_esp, ttp_eng, ttp_description_esp, ttp_description_eng) FROM stdin;
\.
COPY public.mitre_ttp_base (ttp_id, url, mitigation_basic, ttp_esp, ttp_eng, ttp_description_esp, ttp_description_eng) FROM '$$PATH$$/4447.dat';

--
-- Data for Name: nist_base; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.nist_base (nist_id, title) FROM stdin;
\.
COPY public.nist_base (nist_id, title) FROM '$$PATH$$/4454.dat';

--
-- Data for Name: nist_pci_dir; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.nist_pci_dir (nist_id, pci_id) FROM stdin;
\.
COPY public.nist_pci_dir (nist_id, pci_id) FROM '$$PATH$$/4457.dat';

--
-- Data for Name: pci_base; Type: TABLE DATA; Schema: public; Owner: mirmaster
--

COPY public.pci_base (pci_id, title) FROM stdin;
\.
COPY public.pci_base (pci_id, title) FROM '$$PATH$$/4456.dat';

--
-- Name: mitre_aws_dir aws_mitre_dir_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_aws_dir
    ADD CONSTRAINT aws_mitre_dir_pkey PRIMARY KEY (ttp_id, service, event_rule);


--
-- Name: aws_base aws_temp_2_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.aws_base
    ADD CONSTRAINT aws_temp_2_pkey PRIMARY KEY (event_rule, service);


--
-- Name: c5_base c5_base_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.c5_base
    ADD CONSTRAINT c5_base_pkey PRIMARY KEY (c5_id);


--
-- Name: cis_base cis_base_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.cis_base
    ADD CONSTRAINT cis_base_pkey PRIMARY KEY (cis_id);


--
-- Name: cis_nist_dir cis_nist_inh_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.cis_nist_dir
    ADD CONSTRAINT cis_nist_inh_pkey PRIMARY KEY (cis_id, nist_id);


--
-- Name: cis_pci_dir cis_pci_inh_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.cis_pci_dir
    ADD CONSTRAINT cis_pci_inh_pkey PRIMARY KEY (cis_id, pci_id);


--
-- Name: ens_base ens_base_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.ens_base
    ADD CONSTRAINT ens_base_pkey PRIMARY KEY (ens_id);


--
-- Name: mitre_c5_dir mitre_c5_dir_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_c5_dir
    ADD CONSTRAINT mitre_c5_dir_pkey PRIMARY KEY (ttp_id, c5_id);


--
-- Name: mitre_cis_dir mitre_cis_dir_pkey1; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_cis_dir
    ADD CONSTRAINT mitre_cis_dir_pkey1 PRIMARY KEY (ttp_id, cis_id);


--
-- Name: mitre_dir mitre_dir_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_dir
    ADD CONSTRAINT mitre_dir_pkey PRIMARY KEY (ta_id, ttp_id);


--
-- Name: mitre_ens_dir mitre_ens_dir_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_ens_dir
    ADD CONSTRAINT mitre_ens_dir_pkey PRIMARY KEY (ttp_id, ens_id);


--
-- Name: mitre_nist_dir mitre_nist_dir_pkey1; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_nist_dir
    ADD CONSTRAINT mitre_nist_dir_pkey1 PRIMARY KEY (ttp_id, nist_id);


--
-- Name: mitre_pci_dir mitre_pci_dir_pkey1; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_pci_dir
    ADD CONSTRAINT mitre_pci_dir_pkey1 PRIMARY KEY (ttp_id, pci_id);


--
-- Name: mitre_ta_base mitre_ta_base_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_ta_base
    ADD CONSTRAINT mitre_ta_base_pkey PRIMARY KEY (ta_id);


--
-- Name: mitre_ttp_base mitre_ttp_base_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_ttp_base
    ADD CONSTRAINT mitre_ttp_base_pkey PRIMARY KEY (ttp_id);


--
-- Name: nist_base nist_base_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.nist_base
    ADD CONSTRAINT nist_base_pkey PRIMARY KEY (nist_id);


--
-- Name: nist_pci_dir nist_pci_inh_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.nist_pci_dir
    ADD CONSTRAINT nist_pci_inh_pkey PRIMARY KEY (nist_id, pci_id);


--
-- Name: pci_base pci_base_pkey; Type: CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.pci_base
    ADD CONSTRAINT pci_base_pkey PRIMARY KEY (pci_id);


--
-- Name: mitre_c5_dir fk_c5; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_c5_dir
    ADD CONSTRAINT fk_c5 FOREIGN KEY (c5_id) REFERENCES public.c5_base(c5_id);


--
-- Name: mitre_cis_dir fk_cis; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_cis_dir
    ADD CONSTRAINT fk_cis FOREIGN KEY (cis_id) REFERENCES public.cis_base(cis_id);


--
-- Name: mitre_ens_dir fk_ens; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_ens_dir
    ADD CONSTRAINT fk_ens FOREIGN KEY (ens_id) REFERENCES public.ens_base(ens_id);


--
-- Name: mitre_nist_dir fk_nist; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_nist_dir
    ADD CONSTRAINT fk_nist FOREIGN KEY (nist_id) REFERENCES public.nist_base(nist_id);


--
-- Name: mitre_pci_dir fk_pci; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_pci_dir
    ADD CONSTRAINT fk_pci FOREIGN KEY (pci_id) REFERENCES public.pci_base(pci_id);


--
-- Name: mitre_dir fk_ta; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_dir
    ADD CONSTRAINT fk_ta FOREIGN KEY (ta_id) REFERENCES public.mitre_ta_base(ta_id);


--
-- Name: mitre_dir fk_ttp; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);


--
-- Name: mitre_ens_dir fk_ttp; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_ens_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);


--
-- Name: mitre_cis_dir fk_ttp; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_cis_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);


--
-- Name: mitre_pci_dir fk_ttp; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_pci_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);


--
-- Name: mitre_c5_dir fk_ttp; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_c5_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);


--
-- Name: mitre_nist_dir fk_ttp; Type: FK CONSTRAINT; Schema: public; Owner: mirmaster
--

ALTER TABLE ONLY public.mitre_nist_dir
    ADD CONSTRAINT fk_ttp FOREIGN KEY (ttp_id) REFERENCES public.mitre_ttp_base(ttp_id);


--
-- Name: DATABASE vsocmitreintegrationdatabase; Type: ACL; Schema: -; Owner: mirmaster
--

GRANT CONNECT ON DATABASE vsocmitreintegrationdatabase TO mirlambdareader;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: mirmaster
--

REVOKE ALL ON SCHEMA public FROM rdsadmin;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO mirmaster;
GRANT ALL ON SCHEMA public TO PUBLIC;
GRANT USAGE ON SCHEMA public TO mirlambdareader;


--
-- Name: FUNCTION query_export_to_s3(query text, s3_info aws_commons._s3_uri_1, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint); Type: ACL; Schema: aws_s3; Owner: rds_superuser
--

REVOKE ALL ON FUNCTION aws_s3.query_export_to_s3(query text, s3_info aws_commons._s3_uri_1, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.query_export_to_s3(query text, s3_info aws_commons._s3_uri_1, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) TO rds_superuser;


--
-- Name: FUNCTION query_export_to_s3(query text, bucket text, file_path text, region text, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint); Type: ACL; Schema: aws_s3; Owner: rds_superuser
--

REVOKE ALL ON FUNCTION aws_s3.query_export_to_s3(query text, bucket text, file_path text, region text, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.query_export_to_s3(query text, bucket text, file_path text, region text, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) TO rds_superuser;


--
-- Name: FUNCTION table_import_from_s3(table_name text, column_list text, options text, s3_info aws_commons._s3_uri_1, credentials aws_commons._aws_credentials_1); Type: ACL; Schema: aws_s3; Owner: rds_superuser
--

REVOKE ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, s3_info aws_commons._s3_uri_1, credentials aws_commons._aws_credentials_1) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, s3_info aws_commons._s3_uri_1, credentials aws_commons._aws_credentials_1) TO rds_superuser;


--
-- Name: FUNCTION table_import_from_s3(table_name text, column_list text, options text, bucket text, file_path text, region text, access_key text, secret_key text, session_token text); Type: ACL; Schema: aws_s3; Owner: rds_superuser
--

REVOKE ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, bucket text, file_path text, region text, access_key text, secret_key text, session_token text) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, bucket text, file_path text, region text, access_key text, secret_key text, session_token text) TO rds_superuser;


--
-- Name: TABLE aws_base; Type: ACL; Schema: public; Owner: mirmaster
--

GRANT SELECT ON TABLE public.aws_base TO mirlambdareader;


--
-- Name: TABLE mitre_aws_view; Type: ACL; Schema: public; Owner: mirmaster
--

GRANT SELECT ON TABLE public.mitre_aws_view TO mirlambdareader;


--
-- Name: TABLE mitre_ta_base; Type: ACL; Schema: public; Owner: mirmaster
--

GRANT SELECT ON TABLE public.mitre_ta_base TO mirlambdareader;


--
-- Name: TABLE mitre_base_view; Type: ACL; Schema: public; Owner: mirmaster
--

GRANT SELECT ON TABLE public.mitre_base_view TO mirlambdareader;


--
-- Name: TABLE mitre_c5_view; Type: ACL; Schema: public; Owner: mirmaster
--

GRANT SELECT ON TABLE public.mitre_c5_view TO mirlambdareader;


--
-- Name: TABLE mitre_cis_view; Type: ACL; Schema: public; Owner: mirmaster
--

GRANT SELECT ON TABLE public.mitre_cis_view TO mirlambdareader;


--
-- Name: TABLE mitre_ens_view; Type: ACL; Schema: public; Owner: mirmaster
--

GRANT SELECT ON TABLE public.mitre_ens_view TO mirlambdareader;


--
-- Name: TABLE mitre_nist_view; Type: ACL; Schema: public; Owner: mirmaster
--

GRANT SELECT ON TABLE public.mitre_nist_view TO mirlambdareader;


--
-- Name: TABLE mitre_pci_view; Type: ACL; Schema: public; Owner: mirmaster
--

GRANT SELECT ON TABLE public.mitre_pci_view TO mirlambdareader;


--
-- PostgreSQL database dump complete
--

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   