# common/tables/base.py

from django.core.paginator import Paginator
from django.db.models import Q

class HPCTables:
    table_id = None
    table_group = None
    table_label = None

    model = None
    queryset = None

    # optional
    search_fields = []
    default_ordering = None
    page_size = 25
    max_page_size = 200

    # permissions (simple first)
    view_permission = None   # e.g. "inventory.view_device"
    edit_permission = None   # e.g. "inventory.change_device"

    def __init__(self, layout):
        self.layout = layout

    def get_queryset(self):
        if self.queryset is None:
            return self.model.objects.all()
        return self.queryset

    def can_view(self, user) -> bool:
        if not self.view_permission:
            return True
        return user.has_perm(self.view_permission)

    def can_edit(self, user) -> bool:
        if not self.edit_permission:
            return False
        return user.has_perm(self.edit_permission)

    def _apply_search(self, qs, q):
        if not q or not self.search_fields:
            return qs
        cond = Q()
        for f in self.search_fields:
            cond |= Q(**{f"{f}__icontains": q})
        return qs.filter(cond)

    def _apply_sort(self, qs, sort, direction):
        # allow sorting only by declared fields (safe)
        allowed = set(self.layout.value_fields())
        if sort and sort in allowed:
            order = sort if direction == "asc" else f"-{sort}"
            return qs.order_by(order)
        if self.default_ordering:
            return qs.order_by(self.default_ordering)
        return qs

    def fetch(self, *, user, page=1, size=25, q=None, sort=None, direction="asc"):
        qs = self.get_queryset()
        qs = self._apply_search(qs, q)
        qs = self._apply_sort(qs, sort, direction)

        size = min(max(int(size), 1), self.max_page_size)
        page = max(int(page), 1)

        paginator = Paginator(qs, size)
        page_obj = paginator.get_page(page)

        fields = self.layout.value_fields()
        data = list(page_obj.object_list.values(*fields))

        # resolve callbacks
        for c in self.layout.callback_columns():
            out_field = c.field
            src_fields = c.callbacks.get("fields", [])
            func = c.callbacks.get("function")
            for row in data:
                args = [row.get(f) for f in src_fields]
                row[out_field] = func(*args) if func else None

        return {
            "table_id": self.table_id,
            "table_label": self.table_label,
            "columns": self.layout.tabulator_columns(self.can_edit(user)),
            "data": data,
            "page": page,
            "last_page": paginator.num_pages,
            "total": paginator.count,
        }
