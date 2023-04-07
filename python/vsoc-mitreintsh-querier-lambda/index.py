import psycopg2
import logging
from psycopg2 import sql

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_standard_list(cur,view,ttp_id):
    # Gets a list of controls by standard
    try:
        params = (ttp_id,)
        query_5 = sql.SQL("SELECT * FROM {} WHERE ttp_id = %s").format(sql.Identifier(view))
        cur.execute(query_5,params)
    except (Exception, psycopg2.Error) as error:
        logger.error("At query_5: ",error)
    standard_list = [item[1] for item in cur.fetchall()]
    
    return standard_list

def database_handler(event,context):
    rule_event = event['rule']
    eventAction = event['service']
    credential = event['credentials']

    # Colum identifiers
    if credential['lang'] == 'esp':
        ta_n = "ta_esp"
        ta_d = "ta_description_esp"
        m_dt = "m_details_esp"
        ttp_n = "ttp_esp"
        ttp_d = "description_esp"
    else:
        ta_n = "ta_eng"
        ta_d = "ta_description_eng"
        m_dt = "m_details_eng"
        ttp_n = "ttp_eng"
        ttp_d = "description_eng"

    # Declare lists
    db_list_ttp = []
    db_ttp_data = []
    db_list_taid = []
    db_list_taname = []
    db_list_tatype = []
    db_list_taurl = []
    db_list_tadescription = []

    try:
        # Open database connection
        conn = psycopg2.connect(host=credential['host'], user=credential['username'], password=credential['password'], database=credential['db'], connect_timeout=5)

        # Queries
        with conn.cursor() as cur:
            if rule_event == 'update_tactic':
                # Query for TA list
                try:
                    query_1b = sql.SQL("SELECT ta_id,ta_eng,{} FROM mitre_ta_base ORDER BY ta_id").format(sql.Identifier(ta_n))
                    cur.execute(query_1b)
                except (Exception, psycopg2.Error) as error:
                    logger.error("At query_1b: ",error)
                for item in cur.fetchall():
                    db_list_taid.append(item[0])
                    db_list_tatype.append(item[1])
                    db_list_taname.append(item[2])                    

                # Query for TA details
                for ta in db_list_taid:
                    try:
                        params = (ta,)
                        query_2b = sql.SQL("SELECT url,{} FROM mitre_ta_base WHERE ta_id = %s").format(sql.Identifier(ta_d))      
                        cur.execute(query_2b,params)
                    except (Exception, psycopg2.Error) as error:
                        logger.error("At query_2b: ",error)
                    db_ta = cur.fetchone()
                    db_list_taurl.append(db_ta[0])
                    db_list_tadescription.append(db_ta[1])

                db_data = {
                        'db_list_taid': db_list_taid,
                        'db_list_taname': db_list_taname,
                        'db_list_tatype': db_list_tatype,
                        'db_list_taurl': db_list_taurl,
                        'db_list_tadescription': db_list_tadescription
                    }
            else:
                # Query for rule_event details
                try:
                    params = ("%"+eventAction+"%","%"+rule_event+"%")
                    query_1 = sql.SQL("SELECT service,event_rule,{} FROM aws_base WHERE service LIKE %s AND event_rule LIKE %s").format(sql.Identifier(m_dt))
                    cur.execute(query_1,params)
                except (Exception, psycopg2.Error) as error:
                    logger.error("At query_1: ",error)
                db_event = cur.fetchone()

                # Global list of TTPs
                try:
                    params = ("%"+eventAction+"%","%"+rule_event+"%")                
                    query_2 = sql.SQL("SELECT ttp_id FROM mitre_aws_view WHERE service LIKE %s AND event_rule LIKE %s GROUP BY ttp_id")
                    cur.execute(query_2,params)
                except (Exception, psycopg2.Error) as error:
                    logger.error("At query_2: ",error)
                db_list_ttp = [item[0] for item in cur.fetchall()]
            
                # Process TTP list and query for details
                for ttp_id in db_list_ttp:
                    #Recover ttp_id data
                    try:
                        params = (ttp_id,)
                        query_3 = sql.SQL("SELECT ttp_id,{},url,{} FROM mitre_base_view WHERE ttp_id = %s").format(sql.Identifier(ttp_n),sql.Identifier(ttp_d))
                        cur.execute(query_3,params)
                    except (Exception, psycopg2.Error) as error:
                        logger.error("At query_3: ",error)
                    db_ttp = cur.fetchone()
                    
                    # Sub-process to get ta_id and ta_names associates with ttp_id
                    try:
                        db_ttp_tatypelist = []
                        params = (ttp_id,)
                        query_4 = sql.SQL("SELECT ta_eng FROM mitre_base_view WHERE ttp_id = %s")
                        cur.execute(query_4,params)
                    except (Exception, psycopg2.Error) as error:
                        logger.error("At query_4: ",error)
                    for item in cur.fetchall():
                        db_ttp_tatypelist.append(item[0])
                    for new_tatype in db_ttp_tatypelist:
                        if new_tatype not in db_list_tatype:
                            db_list_tatype.append(new_tatype)

                    # Looks for standard control
                    nist_list = get_standard_list(cur,"mitre_nist_view",ttp_id)
                    cis_list = get_standard_list(cur,"mitre_cis_view",ttp_id)
                    pci_list = get_standard_list(cur,"mitre_pci_view",ttp_id)
                    c5_list = get_standard_list(cur,"mitre_c5_view",ttp_id)
                    #iso_list = get_standard_list(cur,"mitre_iso_view",ttp_id)
                    ens_list = get_standard_list(cur,"mitre_ens_view",ttp_id)
                    #standards_list = [nist_list,cis_list,pci_list,c5_list,iso_list,ens_list]
                    standards_list = [nist_list,cis_list,pci_list,c5_list,ens_list]

                    # Fetch with raw data from database this ttp_id [ttp data, associated standards lists, sub ta_id list associated with this ttp, sub ta_name list associated with this ttp]
                    ttp_data = [db_ttp,standards_list,db_ttp_tatypelist]
                    db_ttp_data.append(ttp_data)

                db_data = {
                        'db_event': db_event,
                        'db_ttp_data': db_ttp_data,
                        'db_list_tatype': db_list_tatype
                    }
        return db_data

    except (Exception, psycopg2.Error) as error:
        logger.error("Error while fetching data from PostgreSQL", error)
    
    finally:
        # Close database connection
        if conn:
            cur.close()
            conn.close()
            logger.info("PostgreSQL connection is closed")