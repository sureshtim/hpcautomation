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

    # Apply __filters from query params
    for k, v in request.GET.items():
        if k in ("q",):
            continue
        if "__" in k:
            qs = qs.filter(**{k: v})

    # Apply search
    q_text = request.GET.get("q", "").strip()
    qs = apply_search(qs, q_text, getattr(table, "search_fields", []))

    # Resolve edit permission
    can_edit = False
    edit_perm = getattr(table, "edit_permission", None)
    if edit_perm and hasattr(request, "user"):
        try:
            can_edit = request.user.has_perm(edit_perm)
        except Exception:
            can_edit = False

    # Resolve tabulator columns (same call the view makes)
    tc = getattr(layout, "tabulator_columns", None)
    columns = tc(can_edit) if callable(tc) else (tc or [])

    # Build export columns directly from tabulator_columns so that:
    #   - order matches the view exactly
    #   - hidden columns (visible=False) are excluded
    #   - action-only button columns are excluded
    #   - titles match the column headers the user sees
    export_columns = [
        c for c in columns
        if isinstance(c, dict)
        and c.get("field")
        and c.get("visible", True)
        and c.get("formatter") != "buttonCross"
    ]

    fields = [c["field"] for c in export_columns]
    header = [c.get("title") or c["field"] for c in export_columns]

    # Pass ALL column fields directly to .values() — do NOT validate them
    # against model._meta. Related fields (e.g. "cluster__name") and annotated
    # fields are perfectly valid in .values() even if they don't appear in
    # get_fields() by that exact name.
    values_fields = list(dict.fromkeys(["id"] + fields))  # dedup, id first

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)

    def row_iter():
        yield writer.writerow(header)
        for row in qs.values(*values_fields).iterator(chunk_size=2000):
            yield writer.writerow([row.get(f, "") for f in fields])

    filename = f"{group}_{table_id}.csv"
    resp = StreamingHttpResponse(row_iter(), content_type="text/csv")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp