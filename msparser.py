import os
import sys
import json
import peewee
import logging
import requests

from datetime import datetime

from settings import SETTINGS

from model_ms import MS

logging.basicConfig(format='%(name)s >> [%(asctime)s] :: %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

debug = bool(SETTINGS.get("debug", True))

undefined = SETTINGS.get("undefined", "undefined")

json_filename = SETTINGS.get("json_filename", "snyk.json")

enable_extra_logging = SETTINGS.get("enable_extra_logging", False)
enable_results_logging = SETTINGS.get("enable_results_logging", False)
enable_exception_logging = SETTINGS.get("enable_exception_logging", True)

drop_ms_table_before = SETTINGS.get("drop_ms_table_before", False)

POSTGRES = SETTINGS.get("postgres", {})

pg_default_database = POSTGRES.get("database", "updater_db")
pg_default_user = POSTGRES.get("user", "admin")
pg_default_password = POSTGRES.get("password", "123")
pg_default_host = POSTGRES.get("host", "localhost")
pg_default_port = POSTGRES.get("port", "5432")

pg_drop_before = bool(POSTGRES.get("drop_pg_before", True))

pg_database = os.environ.get("PG_DATABASE", pg_default_database)
pg_user = os.environ.get("PG_USER", pg_default_user)
pg_password = os.environ.get("PG_PASS", pg_default_password)
pg_host = os.environ.get("PG_HOST", pg_default_host)
pg_port = os.environ.get("PG_PORT", pg_default_port)

database = peewee.PostgresqlDatabase(
    database=pg_database,
    user=pg_user,
    password=pg_password,
    host=pg_host,
    port=pg_port
)

SOURCE_NAME = "msbulletin"
SOURCE_FILE = "https://portal.msrc.microsoft.com/api/security-guidance/en-us/"
CURRENT_PATH = os.path.dirname(os.path.realpath(__file__))
GZIP_FILE = os.path.join(CURRENT_PATH, "../data/old_Microsoft_bulletins.gz")


def LOGINFO_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.info(message)

def LOGWARN_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.warning(message)

def LOGERR_IF_ENABLED(message="\n"):
    if enable_exception_logging:
        logger.error(message)

def LOGVAR_IF_ENABLED(message="\n"):
    if enable_results_logging:
        logger.info(message)


def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError

def progress_bar(iteration, total, barLength=50, title="Processing: "):
    percent = int(round((iteration / total) * 100))
    nb_bar_fill = int(round((barLength * percent) / 100))
    bar_fill = '#' * nb_bar_fill
    bar_empty = ' ' * (barLength - nb_bar_fill)
    sys.stdout.write(title + "\r  [{0}] {1}%".format(str(bar_fill + bar_empty), percent))
    sys.stdout.flush()

def get_msbulletin(url, from_date='01/01/1900', to_date=None):
    headers = {
        'Accept': "application/json, text/plain, */*",
        'Content-Type': 'application/json;charset=utf-8',
        'Referer': 'https://portal.msrc.microsoft.com/en-us/security-guidance'
    }

    query = {
        'familyIds': [],
        'productIds': [],
        'severityIds': [],
        'impactIds': [],
        'pageNumber': 1,
        'pageSize': 50000,
        'includeCveNumber': True,
        'includeSeverity': True,
        'includeImpact': True,
        'orderBy': 'publishedDate',
        'orderByMonthly': 'releaseDate',
        'isDescending': True,
        'isDescendingMonthly': True,
        'queryText': '',
        'isSearch': False,
        'filterText': '',
        'fromPublishedDate': from_date
    }

    if to_date:
        query['toPublishedDate'] = to_date

    try:
        post = requests.post(url, headers=headers, data=json.dumps(query))
        if post:
            return post.json()
        else:
            return {}
    except Exception as ex:
        LOGERR_IF_ENABLED("[e] Get an exception with MSBulletin download: {}".format(ex))
        return {}

def connect_database():
    try:
        peewee.logger.disabled = True
        if database.is_closed():
            database.connect()
        else:
            pass
        LOGVAR_IF_ENABLED("[+] Connect Postgres database")
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[e] Connect Postgres database error: {}".format(peewee_operational_error))
    return False


def disconnect_database():
    try:
        if database.is_closed():
            pass
        else:
            database.close()
        LOGVAR_IF_ENABLED("[+] Disconnect Postgres database")
        peewee.logger.disabled = False
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[e] Disconnect Postgres database error: {}".format(peewee_operational_error))
    peewee.logger.disabled = False
    return False

def drop_ms_table():
    connect_database()
    if MS.table_exists():
        MS.drop_table()
    disconnect_database()

def create_ms_table():
    connect_database()
    if not MS.table_exists():
        MS.create_table()
    disconnect_database()

def count_ms_table():
    connect_database()
    count = MS.select().count()
    if count:
        disconnect_database()
        return count
    disconnect_database()
    return 0

def check_if_ms_exists_in_postgres(item_in_json):
    connect_database()
    sid = -1
    if "cve_number" in item_in_json:
        cve_number = item_in_json.get("cve_number")
        knowledge_base_id = item_in_json.get("knowledge_base_id")
        name = item_in_json.get("name")
        family = item_in_json.get("family")
        severity = item_in_json.get("severity")
        impact_id = item_in_json.get("impact_id")
        article_title1 = item_in_json.get("article_title1")
        download_title1 = item_in_json.get("download_title1")
        article_title2 = item_in_json.get("article_title2")
        download_title2 = item_in_json.get("download_title2")
        article_title3 = item_in_json.get("article_title3")
        download_title3 = item_in_json.get("download_title3")
        article_title4 = item_in_json.get("article_title4")
        download_title4 = item_in_json.get("download_title4")
        knowledge_base_id = item_in_json.get("knowledge_base_id")
        monthly_knowledge_base_id = item_in_json.get("monthly_knowledge_base_id")
        if cve_number != "undefined":
            mss = list(
                MS.select().where(
                    (MS.cve_number == cve_number) &
                    (MS.knowledge_base_id == knowledge_base_id) &
                    (MS.name == name) &
                    (MS.family == family) &
                    (MS.severity == severity) &
                    (MS.impact_id == impact_id) &
                    (MS.article_title1 == article_title1) &
                    (MS.article_title2 == article_title2) &
                    (MS.article_title3 == article_title3) &
                    (MS.article_title4 == article_title4) &
                    (MS.download_title1 == download_title1) &
                    (MS.download_title2 == download_title2) &
                    (MS.download_title3 == download_title3) &
                    (MS.download_title4 == download_title4) &
                    (MS.knowledge_base_id == knowledge_base_id) &
                    (MS.monthly_knowledge_base_id == monthly_knowledge_base_id)
                )
            )
            disconnect_database()
            if len(mss) == 0:
                return False, sid
            else:
                return True, mss[0].to_json["id"]

def create_ms_item_in_postgres(item_in_json):
    sid = -1
    connect_database()
    item_in_json["published_date"] = datetime.utcnow() if item_in_json["published_date"] == "undefined" else item_in_json["published_date"]

    ms = MS(
        published_date=item_in_json["published_date"],
        cve_number=item_in_json["cve_number"],
        cve_url=item_in_json["cve_url"],
        name=item_in_json["name"],
        platform=item_in_json["platform"],
        family=item_in_json["family"],
        impact_id=item_in_json["impact_id"],
        impact=item_in_json["impact"],
        severity_id=item_in_json["severity_id"],
        severity=item_in_json["severity"],
        knowledge_base_id=item_in_json["knowledge_base_id"],
        knowledge_base_url=item_in_json["knowledge_base_url"],
        monthly_knowledge_base_id=item_in_json["monthly_knowledge_base_id"],
        monthly_knowledge_base_url=item_in_json["monthly_knowledge_base_url"],
        download_url1=item_in_json["download_url1"],
        download_title1=item_in_json["download_title1"],
        download_url2=item_in_json["download_url2"],
        download_title2=item_in_json["download_title2"],
        download_url3=item_in_json["download_url3"],
        download_title3=item_in_json["download_title3"],
        download_url4=item_in_json["download_url4"],
        download_title4=item_in_json["download_title4"],
        article_title1=item_in_json["article_title1"],
        article_url1=item_in_json["article_url1"],
        article_title2=item_in_json["article_title2"],
        article_url2=item_in_json["article_url2"],
        article_title3=item_in_json["article_title3"],
        article_url3=item_in_json["article_url3"],
        article_title4=item_in_json["article_title4"],
        article_url4=item_in_json["article_url4"],
    )
    ms.save()

    disconnect_database()
    return sid

def update_ms_item_in_postgres(item_in_json, sid):
    connect_database()
    modified = False

    ms = MS.get_by_id(sid)

    if ms.cve_number != item_in_json["cve_number"] or \
        ms.cve_url != item_in_json["cve_url"] or \
        ms.name != item_in_json["name"] or \
        ms.platform != item_in_json["platform"] or \
        ms.family != item_in_json["family"] or \
        ms.impact_id != item_in_json["impact_id"] or \
        ms.impact != item_in_json["impact"] or \
        ms.severity_id != item_in_json["severity_id"] or \
        ms.severity != item_in_json["severity"] or \
        ms.knowledge_base_id != item_in_json["knowledge_base_id"] or \
        ms.knowledge_base_url != item_in_json["knowledge_base_url"] or \
        ms.monthly_knowledge_base_id != item_in_json["monthly_knowledge_base_id"] or \
        ms.monthly_knowledge_base_url != item_in_json["monthly_knowledge_base_url"] or \
        ms.download_url1 != item_in_json["download_url1"] or \
        ms.download_title1 != item_in_json["download_title1"] or \
        ms.download_url2 != item_in_json["download_url2"] or \
        ms.download_title2 != item_in_json["download_title2"] or \
        ms.download_url3 != item_in_json["download_url3"] or \
        ms.download_title3 != item_in_json["download_title3"] or \
        ms.download_url4 != item_in_json["download_url4"] or \
        ms.download_title4 != item_in_json["download_title4"] or \
        ms.article_url1 != item_in_json["article_url1"] or \
        ms.article_title1 != item_in_json["article_title1"] or \
        ms.article_url2 != item_in_json["article_url2"] or \
        ms.article_title2 != item_in_json["article_title2"] or \
        ms.article_url3 != item_in_json["article_url3"] or \
        ms.article_title3 != item_in_json["article_title3"] or \
        ms.article_url4 != item_in_json["article_url4"] or \
            ms.article_title4 != item_in_json["article_title4"]:
        modified = True

    if modified:
        item_in_json["published_date"] = datetime.utcnow() if item_in_json["published_date"] == "undefined" else item_in_json["published_date"]
        ms.cve_number = item_in_json["cve_number"]
        ms.cve_url = item_in_json["cve_url"]
        ms.name = item_in_json["name"]
        ms.platform = item_in_json["platform"]
        ms.family = item_in_json["family"]
        ms.impact_id = item_in_json["impact_id"]
        ms.impact = item_in_json["impact"]
        ms.severity_id = item_in_json["severity_id"]
        ms.severity = item_in_json["severity"]
        ms.knowledge_base_id = item_in_json["knowledge_base_id"]
        ms.knowledge_base_url = item_in_json["knowledge_base_url"]
        ms.monthly_knowledge_base_id = item_in_json["monthly_knowledge_base_id"]
        ms.monthly_knowledge_base_url = item_in_json["monthly_knowledge_base_url"]
        ms.download_url1 = item_in_json["download_url1"]
        ms.download_title1 = item_in_json["download_title1"]
        ms.download_url2 = item_in_json["download_url2"]
        ms.download_title2 = item_in_json["download_title2"]
        ms.download_url3 = item_in_json["download_url3"]
        ms.download_title3 = item_in_json["download_title3"]
        ms.download_url4 = item_in_json["download_url4"]
        ms.download_title4 = item_in_json["download_title4"]
        ms.article_url1 = item_in_json["article_url1"]
        ms.article_title1 = item_in_json["article_title1"]
        ms.article_url2 = item_in_json["article_url2"]
        ms.article_title2 = item_in_json["article_title2"]
        ms.article_url3 = item_in_json["article_url3"]
        ms.article_title3 = item_in_json["article_title3"]
        ms.article_url4 = item_in_json["article_url4"]
        ms.article_title4 = item_in_json["article_title4"]
        ms.save()

    disconnect_database()
    if modified:
        return "modified"
    return "skipped"

def create_of_update_ms_item_in_postgres(item_in_json):
    exists, sid = check_if_ms_exists_in_postgres(item_in_json)
    if exists and sid != -1:
        result = update_ms_item_in_postgres(item_in_json, sid)
        return result, sid
    elif not exists and sid == -1:
        sid = create_ms_item_in_postgres(item_in_json)
        return "created", sid

def update_ms_vulners():
    data_json = get_msbulletin(SOURCE_FILE)
    if isinstance(data_json, dict):
        count = data_json.get("count", 0)
        LOGINFO_IF_ENABLED("[+] Get {} vulnerabilities from MS database".format(count))
        # with open("ms.json", "w") as mf:
        #     json.dump(data_json, mf)
        if count > 0:
            details = data_json.get("details", [])
            if len(details) != 0:
                created = []
                modified = []
                skipped = []
                for item_in_details in details:

                    item_in_json = dict()

                    item_in_json["published_date"] = item_in_details.get("publishedDate", undefined)

                    item_in_json["cve_number"] = item_in_details.get("cveNumber", undefined)

                    item_in_json["cve_url"] = item_in_details.get("cveUrl", undefined)

                    item_in_json["name"] = item_in_details.get("name", undefined)

                    item_in_json["platform"] = item_in_details.get("platform", None)
                    if item_in_json["platform"] is None:
                        item_in_json["platform"] = undefined

                    item_in_json["family"] = item_in_details.get("family", None)
                    if item_in_json["family"] is None or item_in_json["family"] == "":
                        item_in_json["family"] = undefined

                    item_in_json["impact_id"] = item_in_details.get("impactId", None)
                    if item_in_json["impact_id"] is None or item_in_json["impact_id"] == "":
                        item_in_json["impact_id"] = undefined

                    item_in_json["impact"] = item_in_details.get("impact", None)
                    if item_in_json["impact"] is None or item_in_json["impact"] == "":
                        item_in_json["impact"] = undefined

                    item_in_json["severity_id"] = item_in_details.get("severityId", None)
                    if item_in_json["severity_id"] is None or item_in_json["severity_id"] == "":
                        item_in_json["severity_id"] = undefined

                    item_in_json["severity"] = item_in_details.get("severity", None)
                    if item_in_json["severity"] is None or item_in_json["severity"] == "":
                        item_in_json["severity"] = undefined

                    item_in_json["knowledge_base_id"] = item_in_details.get("knowledgeBaseId", None)
                    if item_in_json["knowledge_base_id"] is None or item_in_json["knowledge_base_id"] == "":
                        item_in_json["knowledge_base_id"] = undefined

                    item_in_json["knowledge_base_url"] = item_in_details.get("knowledgeBaseUrl", None)
                    if item_in_json["knowledge_base_url"] is None or ' ' in item_in_json["knowledge_base_url"]:
                        item_in_json["knowledge_base_url"] = undefined

                    item_in_json["monthly_knowledge_base_id"] = item_in_details.get("monthlyKnowledgeBaseId", None)
                    if item_in_json["monthly_knowledge_base_id"] is None or item_in_json["monthly_knowledge_base_id"] == "":
                        item_in_json["monthly_knowledge_base_id"] = undefined

                    item_in_json["monthly_knowledge_base_url"] = item_in_details.get("monthlyKnowledgeBaseUrl", None)
                    if item_in_json["monthly_knowledge_base_url"] is None or ' 'in item_in_json["monthly_knowledge_base_url"]:
                        item_in_json["monthly_knowledge_base_url"] = undefined

                    item_in_json["article_title1"] = item_in_details.get("articleTitle1", None)
                    if item_in_json["article_title1"] is None or item_in_json["article_title1"] == "":
                        item_in_json["article_title1"] = undefined

                    item_in_json["article_url1"] = item_in_details.get("articleUrl1", None)
                    if item_in_json["article_url1"] is None or ' ' in item_in_json["article_url1"]:
                        item_in_json["article_url1"] = undefined

                    item_in_json["article_title2"] = item_in_details.get("articleTitle2", None)
                    if item_in_json["article_title2"] is None or item_in_json["article_title2"] == "":
                        item_in_json["article_title2"] = undefined

                    item_in_json["article_url2"] = item_in_details.get("articleUrl2", None)
                    if item_in_json["article_url2"] is None or ' ' in item_in_json["article_url2"]:
                        item_in_json["article_url2"] = undefined

                    item_in_json["article_title3"] = item_in_details.get("articleTitle3", None)
                    if item_in_json["article_title3"] is None or item_in_json["article_title3"] == "":
                        item_in_json["article_title3"] = undefined

                    item_in_json["article_url3"] = item_in_details.get("articleUrl3", None)
                    if item_in_json["article_url3"] is None or ' ' in item_in_json["article_url3"]:
                        item_in_json["article_url3"] = undefined

                    item_in_json["article_title4"] = item_in_details.get("articleTitle4", None)
                    if item_in_json["article_title4"] is None or item_in_json["article_title4"] == "":
                        item_in_json["article_title4"] = undefined

                    item_in_json["article_url4"] = item_in_details.get("articleUrl4", None)
                    if item_in_json["article_url4"] is None or ' ' in item_in_json["article_url4"]:
                        item_in_json["article_url4"] = undefined

                    item_in_json["download_title1"] = item_in_details.get("downloadTitle1", None)
                    if item_in_json["download_title1"] is None or item_in_json["download_title1"]:
                        item_in_json["download_title1"] = undefined

                    item_in_json["download_url1"] = item_in_details.get("downloadUrl1", None)
                    if item_in_json["download_url1"] is None or ' ' in item_in_json["download_url1"]:
                        item_in_json["download_url1"] = undefined

                    item_in_json["download_title2"] = item_in_details.get("downloadTitle2", None)
                    if item_in_json["download_title2"] is None or item_in_json["download_title2"] == "":
                        item_in_json["download_title2"] = undefined

                    item_in_json["download_url2"] = item_in_details.get("downloadUrl2", None)
                    if item_in_json["download_url2"] is None or ' ' in item_in_json["download_url2"]:
                        item_in_json["download_url2"] = undefined

                    item_in_json["download_title3"] = item_in_details.get("downloadTitle3", None)
                    if item_in_json["download_title3"] is None or item_in_json["download_title3"] == "":
                        item_in_json["download_title3"] = undefined

                    item_in_json["download_url3"] = item_in_details.get("downloadUrl3", None)
                    if item_in_json["download_url3"] is None or ' ' in item_in_json["download_url3"]:
                        item_in_json["download_url3"] = undefined

                    item_in_json["download_title4"] = item_in_details.get("downloadTitle4", None)
                    if item_in_json["download_title4"] is None or item_in_json["download_title4"] == "":
                        item_in_json["download_title4"] = undefined

                    item_in_json["download_url4"] = item_in_details.get("downloadUrl4", None)
                    if item_in_json["download_url4"] is None or ' ' in item_in_json["download_url4"]:
                        item_in_json["download_url4"] = undefined

                    result, sid = create_of_update_ms_item_in_postgres(item_in_json)

                    if result == "created":
                        created.append(item_in_json)
                    elif result == "modified":
                        modified.append(item_in_json)
                    else:
                        skipped.append(item_in_json)

                LOGINFO_IF_ENABLED("[+] Create {} vulnerabilities".format(len(created)))
                LOGINFO_IF_ENABLED("[+] Modify {} vulnerabilities".format(len(modified)))
                LOGINFO_IF_ENABLED("[+] Skip   {} vulnerabilities".format(len(skipped)))
            else:
                LOGERR_IF_ENABLED("[e] Get empty data set from MS source")
        else:
            LOGERR_IF_ENABLED("[e] Get 0 items from MS source")
    else:
        LOGERR_IF_ENABLED("[e] Get not JSON data from MS source")

def run():
    if drop_ms_table_before:
        drop_ms_table()
        create_ms_table()

    update_ms_vulners()

def main():
    run()


if __name__ == "__main__":
    main()

