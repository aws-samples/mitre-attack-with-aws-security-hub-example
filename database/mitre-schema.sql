toc.dat                                                                                             0000600 0004000 0002000 00000066204 14362250261 0014450 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        PGDMP                            {            vsocmitreintegrationdatabase    14.4    14.4 O    Z           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false         [           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false         \           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false         ]           1262    16639    vsocmitreintegrationdatabase    DATABASE     q   CREATE DATABASE vsocmitreintegrationdatabase WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'en_US.UTF-8';
 ,   DROP DATABASE vsocmitreintegrationdatabase;
             	   mirmaster    false         ^           0    0 %   DATABASE vsocmitreintegrationdatabase    ACL     K   GRANT CONNECT ON DATABASE vsocmitreintegrationdatabase TO mirlambdareader;
                	   mirmaster    false    4445         _           0    0    SCHEMA public    ACL     �   REVOKE ALL ON SCHEMA public FROM rdsadmin;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO mirmaster;
GRANT ALL ON SCHEMA public TO PUBLIC;
GRANT USAGE ON SCHEMA public TO mirlambdareader;
                	   mirmaster    false    5                     3079    16640    aws_commons 	   EXTENSION     ?   CREATE EXTENSION IF NOT EXISTS aws_commons WITH SCHEMA public;
    DROP EXTENSION aws_commons;
                   false         `           0    0    EXTENSION aws_commons    COMMENT     M   COMMENT ON EXTENSION aws_commons IS 'Common data types across AWS services';
                        false    2                     3079    16654    aws_s3 	   EXTENSION     :   CREATE EXTENSION IF NOT EXISTS aws_s3 WITH SCHEMA public;
    DROP EXTENSION aws_s3;
                   false    2         a           0    0    EXTENSION aws_s3    COMMENT     N   COMMENT ON EXTENSION aws_s3 IS 'AWS S3 extension for importing data from S3';
                        false    3         b           0    0 �   FUNCTION query_export_to_s3(query text, s3_info aws_commons._s3_uri_1, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint)    ACL     �  REVOKE ALL ON FUNCTION aws_s3.query_export_to_s3(query text, s3_info aws_commons._s3_uri_1, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.query_export_to_s3(query text, s3_info aws_commons._s3_uri_1, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) TO rds_superuser;
          aws_s3          rds_superuser    false    257         c           0    0 �   FUNCTION query_export_to_s3(query text, bucket text, file_path text, region text, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint)    ACL     �  REVOKE ALL ON FUNCTION aws_s3.query_export_to_s3(query text, bucket text, file_path text, region text, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.query_export_to_s3(query text, bucket text, file_path text, region text, options text, OUT rows_uploaded bigint, OUT files_uploaded bigint, OUT bytes_uploaded bigint) TO rds_superuser;
          aws_s3          rds_superuser    false    258         d           0    0 �   FUNCTION table_import_from_s3(table_name text, column_list text, options text, s3_info aws_commons._s3_uri_1, credentials aws_commons._aws_credentials_1)    ACL     ~  REVOKE ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, s3_info aws_commons._s3_uri_1, credentials aws_commons._aws_credentials_1) FROM rdsadmin;
GRANT ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, s3_info aws_commons._s3_uri_1, credentials aws_commons._aws_credentials_1) TO rds_superuser;
          aws_s3          rds_superuser    false    256         e           0    0 �   FUNCTION table_import_from_s3(table_name text, column_list text, options text, bucket text, file_path text, region text, access_key text, secret_key text, session_token text)    ACL     �  REVOKE ALL ON FUNCTION aws_s3.table_import_from_s3(table_name text, column_list text, options text, bucket text, file_path text, region text, access_key text, secret_key text, session_token text) FROM rdsadmin;
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
       public         heap 	   mirmaster    false         f           0    0    TABLE aws_base    ACL     :   GRANT SELECT ON TABLE public.aws_base TO mirlambdareader;
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
       public       	   mirmaster    false    222    222    216    222    216    223    223    223    216    216    216         g           0    0    TABLE mitre_aws_view    ACL     @   GRANT SELECT ON TABLE public.mitre_aws_view TO mirlambdareader;
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
       public         heap 	   mirmaster    false         h           0    0    TABLE mitre_ta_base    ACL     ?   GRANT SELECT ON TABLE public.mitre_ta_base TO mirlambdareader;
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
       public       	   mirmaster    false    225    223    223    223    223    223    223    223    225    225    224    224         i           0    0    TABLE mitre_base_view    ACL     A   GRANT SELECT ON TABLE public.mitre_base_view TO mirlambdareader;
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
       public       	   mirmaster    false    226    217    226    217         j           0    0    TABLE mitre_c5_view    ACL     ?   GRANT SELECT ON TABLE public.mitre_c5_view TO mirlambdareader;
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
       public       	   mirmaster    false    218    218    228    228         k           0    0    TABLE mitre_cis_view    ACL     @   GRANT SELECT ON TABLE public.mitre_cis_view TO mirlambdareader;
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
       public       	   mirmaster    false    230    221    221    230         l           0    0    TABLE mitre_ens_view    ACL     @   GRANT SELECT ON TABLE public.mitre_ens_view TO mirlambdareader;
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
       public       	   mirmaster    false    232    232    233    233         m           0    0    TABLE mitre_nist_view    ACL     A   GRANT SELECT ON TABLE public.mitre_nist_view TO mirlambdareader;
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
       public       	   mirmaster    false    236    235    235    236         n           0    0    TABLE mitre_pci_view    ACL     @   GRANT SELECT ON TABLE public.mitre_pci_view TO mirlambdareader;
          public       	   mirmaster    false    237         �            1259    16755    nist_pci_dir    TABLE     |   CREATE TABLE public.nist_pci_dir (
    nist_id character varying(10) NOT NULL,
    pci_id character varying(10) NOT NULL
);
     DROP TABLE public.nist_pci_dir;
       public         heap 	   mirmaster    false         �           2606    16759     mitre_aws_dir aws_mitre_dir_pkey 
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
       public       	   mirmaster    false    232    223    4261                                                                                                                                                                                                                                                                                                                                                                                                    restore.sql                                                                                         0000600 0004000 0002000 00000052600 14362250261 0015370 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        --
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

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                