import os
import peewee
from playhouse.postgres_ext import ArrayField
from datetime import datetime

from settings import SETTINGS

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


class MS(peewee.Model):
    class Meta:
        database = database
        ordering = ("ms_id", )
        table_name = "vilnerabilities_ms"

    id = peewee.PrimaryKeyField(null=False)
    published_date = peewee.DateTimeField(default=datetime.now, verbose_name="Published date")
    cve_number = peewee.TextField(default="")
    cve_url = peewee.TextField(default="")
    name = peewee.TextField(default="")
    platform = peewee.TextField(default="")
    family = peewee.TextField(default="")
    impact_id = peewee.TextField(default="")
    impact = peewee.TextField(default="")
    severity_id = peewee.TextField(default="")
    severity = peewee.TextField(default="")
    knowledge_base_id = peewee.TextField(default="")
    knowledge_base_url = peewee.TextField(default="")
    monthly_knowledge_base_id = peewee.TextField(default="")
    monthly_knowledge_base_url = peewee.TextField(default="")
    download_url = ArrayField(peewee.TextField, default=[])
    download_title = ArrayField(peewee.TextField, default=[])
    article_title = ArrayField(peewee.TextField, default=[])
    article_url =ArrayField(peewee.TextField, default=[])
    does_row_one_have_at_least_one_article_or_url = peewee.BooleanField(default=False)
    does_row_two_have_at_least_one_article_or_url = peewee.BooleanField(default=False)
    does_row_three_have_at_least_one_article_or_url = peewee.BooleanField(default=False)
    does_row_four_have_at_least_one_article_or_url = peewee.BooleanField(default=False)
    count_of_rows_with_at_least_one_article_or_url = peewee.IntegerField(default=0)

    def __unicode__(self):
        return "ms"

    def __str__(self):
        return str(self.ms_id)

    @property
    def to_json(self):
        return dict(
            id=self.id,
            published_date=self.published_date,
            cve_number=self.cve_number,
            cve_url=self.cve_url,
            name=self.name,
            platform=self.platform,
            family=self.family,
            impact_id=self.impact_id,
            impact=self.impact,
            severity_id=self.severity_id,
            severity=self.severity,
            knowledge_base_id=self.knowledge_base_id,
            knowledge_base_url=self.knowledge_base_url,
            monthly_knowledge_base_id=self.monthly_knowledge_base_id,
            monthly_knowledge_base_url=self.monthly_knowledge_base_url,
            download_url=self.download_url,
            download_title=self.download_title,
            article_title=self.article_title,
            article_url=self.article_url,
            does_row_one_have_at_least_one_article_or_url=self.does_row_one_have_at_least_one_article_or_url,
            does_row_two_have_at_least_one_article_or_url=self.does_row_two_have_at_least_one_article_or_url,
            does_row_three_have_at_least_one_article_or_url=self.does_row_three_have_at_least_one_article_or_url,
            does_row_four_have_at_least_one_article_or_url=self.does_row_four_have_at_least_one_article_or_url,
            count_of_rows_with_at_least_one_article_or_url=self.count_of_rows_with_at_least_one_article_or_url
        )