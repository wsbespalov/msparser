import os
import re
import json
import time
import gzip
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
GZIP_FILE = os.path.join(CURRENT_PATH,"../data/old_Microsoft_bulletins.gz")


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
        LOGERR_IF_ENABLED("[e] Get an exceptino with MSBulletin download: {}".format(ex))
        return {}

def connect_database():
    try:
        peewee.logger.disabled = True
        if database.is_closed():
            database.connect()
        else:
            pass
        LOGVAR_IF_ENABLED("[+] Connect Postgress database")
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
        LOGVAR_IF_ENABLED("[+] Disconnect Postgress database")
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
    mss = []

    return False, -1

def create_ms_item_in_postgres(item_in_json):
    sid = -1

    return sid

def update_ms_item_in_postgres(item_in_json, sid):
    # return "modified"
    return "skipped"

def create_of_update_ms_item_in_postgres(item_in_json):
    exists, sid = check_if_ms_exists_in_postgres(item_in_json)
    if exists and sid != -1:
        result = update_ms_item_in_postgres(item_in_json)
        return result, sid
    elif not exists and sid == -1:
        sid = create_ms_item_in_postgres(item_in_json)
        return "created", sid

def update_ms_vulners():
    data_json = get_msbulletin(SOURCE_FILE)
    if isinstance(data_json, dict):
        count = data_json.get("count", 0)
        LOGINFO_IF_ENABLED("[+] Get {} vilnerabilities from MS database".format(count))
        if count > 0:
            details = data_json.get("details", [])
            if len(details) != 0:
                # parse
                created = []
                modified = []
                skipped = []
                for item_in_details in details:
                    item_in_json = dict()
                    item_in_json["published_date"] = item_in_details.get("publishedDate", datetime.utcnow())
                    item_in_json["cve_number"] = item_in_details.get("cveNumber", "undefined")
                    item_in_json["cve_url"] = item_in_details.get("cveUrl", "undefined")
                    item_in_json["name"] = item_in_details.get("name", "undefined")
                    item_in_json["platform"] = item_in_details.get("platform", None)
                    if item_in_json["platform"] is None:
                        item_in_json["platform"] = "undefined"
                    item_in_json["family"] = item_in_details.get("family", None)
                    if item_in_json["family"] is None:
                        item_in_json["family"] = None
                    item_in_json["impact_id"] = item_in_details.get("impactId", None)
                    if item_in_json["impact_id"] is None:
                        item_in_json["impact_id"] = "undefined"
                    item_in_json["impact"] = item_in_details.get("impact", None)
                    if item_in_json["impact"] is None:
                        item_in_json["impact"] = "undefined"
                    item_in_json["severity_id"] = item_in_details.get("severityId", None)
                    if item_in_json["severity_id"] is None:
                        item_in_json["severity_id"] = "indefined"
                    item_in_json["severity"] = item_in_details.get("severity", None)
                    if item_in_json["severity"] is None:
                        item_in_json["severity"] = "undefined"
                    item_in_json["knowledge_base_id"] = item_in_details.get("knowledgeBaseId", None)
                    if item_in_json["knowledge_base_id"] is None:
                        item_in_json["knowledge_base_id"] = "undefined"
                    item_in_json["knowledge_base_url"] = item_in_details.get("knowledgeBaseUrl", None)
                    if item_in_json["knowledge_base_url"] is None:
                        item_in_json["knowledge_base_url"] = "undefined"
                    item_in_json["monthly_knowledge_base_id"] = item_in_details.get("monthlyKnowledgeBaseId", None)
                    if item_in_json["monthly_knowledge_base_id"] is None:
                        item_in_json["monthly_knowledge_base_id"] = "undefined"
                    item_in_json["monthly_knowledge_base_url"] = item_in_details.get("monthlyKnowledgeBaseUrl", None)
                    if item_in_json["monthly_knowledge_base_url"] is None:
                        item_in_json["monthly_knowledge_base_url"] = "undefined"
                    item_in_json["does_row_one_have_at_least_one_article_or_url"] = item_in_details.get("doesRowOneHaveAtLeastOneArticleOrUrl", False)
                    item_in_json["does_row_two_have_at_least_one_article_or_url"] = item_in_details.get("doesRowTwoHaveAtLeastOneArticleOrUrl", False)
                    item_in_json["does_row_three_have_at_least_one_article_or_url"] = item_in_details.get("doesRowThreeHaveAtLeastOneArticleOrUrl", False)
                    item_in_json["does_row_four_have_at_least_one_article_or_url"] = item_in_details.get("doesRowFourHaveAtLeastOneArticleOrUrl", False)
                    item_in_json["count_of_rows_with_at_least_one_article_or_url"] = item_in_details.get("countOfRowsWithAtLeastOneArticleOrUrl", 0)
                    download_url = []
                    download_title = []
                    article_title = []
                    article_url = []
                    if item_in_json["does_row_one_have_at_least_one_article_or_url"]:
                        article_title.append(item_in_details.get("articleTitle1", ""))
                        article_url.append(item_in_details.get("articleUrl1", ""))
                        download_title.append(item_in_details.get("downloadTitle1", ""))
                        download_url.append(item_in_details.get("downloadUrl1", ""))
                    if item_in_json["does_row_two_have_at_least_one_article_or_url"]:
                        article_title.append(item_in_details.get("articleTitle2", ""))
                        article_url.append(item_in_details.get("articleUrl2", ""))
                        download_title.append(item_in_details.get("downloadTitle2", ""))
                        download_url.append(item_in_details.get("downloadUrl2", ""))
                    if item_in_json["does_row_three_have_at_least_one_article_or_url"]:
                        article_title.append(item_in_details.get("articleTitle3", ""))
                        article_url.append(item_in_details.get("articleUrl3", ""))
                        download_title.append(item_in_details.get("downloadTitle3", ""))
                        download_url.append(item_in_details.get("downloadUrl3", ""))
                    if item_in_json["does_row_four_have_at_least_one_article_or_url"]:
                        article_title.append(item_in_details.get("articleTitle4", ""))
                        article_url.append(item_in_details.get("articleUrl4", ""))
                        download_title.append(item_in_details.get("downloadTitle4", ""))
                        download_url.append(item_in_details.get("downloadUrl4", ""))
                    item_in_json["download_url"] = download_url
                    item_in_json["download_title"] = download_title
                    item_in_json["article_url"] = article_url
                    item_in_json["article_title"] = article_title

                    result, sid = create_of_update_ms_item_in_postgres(item_in_json)

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

