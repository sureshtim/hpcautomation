from django.http import JsonResponse
from django.db.models import Q

from common.tables.registry import get_table


def _apply_search(qs, q_text, fields):
    if not q_text or not fields:
        return qs
    q_obj = Q()
    for f in fields:
        q_obj |= Q(**{f"{f}__icontains": q_text})
    return qs.filter(q_obj)


def _get_layout_columns(layout):
    """
    ColumnLayout in your project does NOT have get_columns().
    So we grab the underlying list of column objects.
    """
    for attr in ("columns", "column_obj", "cols", "items", "column_list"):
        if hasattr(layout, attr):
            cols = getattr(layout, attr)
            if callable(cols):
                cols = cols()
            if isinstance(cols, (list, tuple)):
                return list(cols)
    # fallback: if it is iterable
    try:
        return list(layout)
    except Exception:
        return []


def _col_to_tabulator(col):
    """
    Convert your Column objects into Tabulator column dict.
    Tries to read common attributes.
    """
    d = {}

    # required
    d["title"] = getattr(col, "title", None) or getattr(col, "label", None) or "Column"
    d["field"] = getattr(col, "field", None)

    # optional
    for k in ("frozen", "hozAlign", "formatter", "formatterParams", "editor",
              "editorParams", "headerFilter", "headerFilterFunc", "headerSort",
              "minWidth", "width", "visible"):
        if hasattr(col, k):
            v = getattr(col, k)
            # skip None
            if v is not None:
                d[k] = v

    # sensible defaults for filtering if not already set
    if "headerFilter" not in d:
        d["headerFilter"] = "input"
    if "headerFilterFunc" not in d:
        d["headerFilterFunc"] = "like"

    return d


def table_api(request, group, table_id):
    TableCls = get_table(group, table_id)
    if not TableCls:
        return JsonResponse({"detail": "Table not found"}, status=404)

    table = TableCls()
    layout = getattr(table, "layout", None)
    if layout is None:
        return JsonResponse(
            {"detail": "Table layout not defined. In table __init__, set self.layout = ColumnLayout(...)"},
            status=500,
        )

    # pagination/progressive scroll params
    page = int(request.GET.get("page", 1))
    size = int(request.GET.get("size", 200))

    qs = table.queryset

    # allow django filters in query params
    for k, v in request.GET.items():
        if k in ("page", "size", "q"):
            continue
        if "__" in k:
            qs = qs.filter(**{k: v})
        else:
            qs = qs.filter(**{k: v})

    # search
    q_text = request.GET.get("q", "").strip()
    qs = _apply_search(qs, q_text, getattr(table, "search_fields", []))

    # Build column definitions from your Column objects
    col_objs = _get_layout_columns(layout)
    if not col_objs:
        return JsonResponse({"detail": "No columns found in layout"}, status=500)

    columns = [_col_to_tabulator(c) for c in col_objs]

    # derive fields to fetch
    fields = [c["field"] for c in columns if c.get("field")]
    if "id" not in fields:
        fields.append("id")

    total = qs.count()
    last_page = max(1, (total + size - 1) // size)

    start = (page - 1) * size
    end = start + size

    data = list(qs.values(*fields)[start:end])

    return JsonResponse(
        {
            "columns": columns,
            "data": data,
            "last_page": last_page,
            "tabulator_settings": getattr(table, "tabulator_settings", {}),
        },
        safe=False,
    )
