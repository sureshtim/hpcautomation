from django.urls import path
from common.tables.views import TablePageView
from common.tables.api import table_api
from common.tables.exports import table_export_csv

urlpatterns = [
    # HTML page
    path("tables/<str:group>/<str:table_id>/", TablePageView.as_view(), name="table_page"),

    # API data
    path("api/tables/<str:group>/<str:table_id>/", table_api, name="table_api"),

    # Export CSV (ALL rows)
    path(
        "api/tables/<str:group>/<str:table_id>/export/csv/",
        table_export_csv,
        name="table_export_csv",
    ),
]
