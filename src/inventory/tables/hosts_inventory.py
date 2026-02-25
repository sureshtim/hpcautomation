from common.tables.base import HPCTables
from common.tables.layout import ColumnLayout
from common.tables.columns import Column, TextAreaColumn, TimeColumn
from common.tables.registry import register_table

from inventory.models import Host

@register_table
class HostTableView(HPCTables):
    table_group = "hosts"
    table_id = "inventory"
    table_label = "Compute Inventory"
    # http://127.0.0.1:8001/tables/hosts/inventory/

    model = Host
    queryset = (
        Host.objects.select_related("cluster").all().order_by("cluster__name", "hostname")
    )

    view_permission = "inventory.view_hosts_inventory"
    edit_permission = None

    tabulator_settings = {
        "progressiveLoad": "scroll",
        "paginationMode": "remote",
        "paginationSize": 500,
        "progressiveLoadScrollMargin": 400,
        "filterMode": "remote",
    }

#     tabulator_settings = {
#     "pagination": False,
# }

    search_fields = [
        "hostname", "status", "host_type", "serialnumber", "asset_tag",
        "hw_model", "bios_version", "location", "rack", "quad", "shelf",
    ]

    def __init__(self):
        self.layout = ColumnLayout(
            Column(title="Cluster", field="cluster__name", frozen=True, editable=False),
            Column(title="Host Name", field="hostname", frozen=True),
            Column(title="OS", field="os_type"),
            Column(title="Kernal", field="kernal_version"),
            Column(title="Host Type", field="host_type"),
            Column(title="Status", field="status"),
            Column(title="Serial Number", field="serialnumber"),
            Column(title="Asset Tag", field="asset_tag"),
            Column(title="Model", field="hw_model"),
            Column(title="BIOS Version", field="bios_version"),
            Column(title="Location", field="location"),
            Column(title="Rack", field="rack"),
            Column(title="Quad", field="quad"),
            Column(title="Shelf", field="shelf"),
            Column(title="Used For", field="used_for"),
        )
        super().__init__(self.layout)