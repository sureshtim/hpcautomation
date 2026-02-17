import csv
from django.http import StreamingHttpResponse, JsonResponse
from django.db.models import Q

from common.tables.registry import get_table


def apply_search(qs, q_text, fields):
    if not q_text or not fields:
        return qs
    q_obj = Q()
    for f in fields:
        q_obj |= Q(**{f"{f}__icontains": q_text})
    return qs.filter(q_obj)


class Echo:
    def write(self, value):
        return value


def table_export_csv(request, group, table_id):
    TableCls = get_table(group, table_id)
    if not TableCls:
        return JsonResponse({"detail": "Table not found"}, status=404)

    table = TableCls()
    layout = getattr(table, "layout", None)
    if layout is None:
        return JsonResponse({"detail": "Table layout missing"}, status=500)

    qs = table.queryset

    # allow __filters
    for k, v in request.GET.items():
        if k in ("q",):
            continue
        if "__" in k:
            qs = qs.filter(**{k: v})

    # search
    q_text = request.GET.get("q", "").strip()
    qs = apply_search(qs, q_text, getattr(table, "search_fields", []))

    # ---- permissions (optional) ----
    # If your table defines edit_permission, use the current user.
    can_edit = False
    edit_perm = getattr(table, "edit_permission", None)
    if edit_perm and hasattr(request, "user"):
        try:
            can_edit = request.user.has_perm(edit_perm)
        except Exception:
            can_edit = False

    # ---- tabulator columns ----
    tc = getattr(layout, "tabulator_columns", None)
    if callable(tc):
        # your ColumnLayout expects: tabulator_columns(can_edit_table)
        columns = tc(can_edit)
    else:
        columns = tc or []

    # ---- value fields ----
    vf = getattr(layout, "value_fields", [])
    fields = list(vf() if callable(vf) else vf)
    if "id" not in fields:
        fields.append("id")

    # Header row: use column titles where possible
    title_by_field = {}
    for c in columns or []:
        if isinstance(c, dict) and c.get("field"):
            title_by_field[c["field"]] = c.get("title", c["field"])

    header = [title_by_field.get(f, f) for f in fields]

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)

    def row_iter():
        yield writer.writerow(header)
        for row in qs.values(*fields).iterator(chunk_size=2000):
            yield writer.writerow([row.get(f, "") for f in fields])

    filename = f"{group}_{table_id}.csv"
    resp = StreamingHttpResponse(row_iter(), content_type="text/csv")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
