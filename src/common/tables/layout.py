# common/tables/layout.py

class ColumnLayout:
    def __init__(self, *columns):
        self.columns = list(columns)

    def tabulator_columns(self, can_edit_table: bool):
        return [c.to_tabulator(can_edit_table) for c in self.columns]

    def value_fields(self):
        """
        Fields to fetch from Django queryset.
        Include callback source fields too.
        """
        fields = set()
        for c in self.columns:
            if c.callbacks:
                for f in c.callbacks.get("fields", []):
                    fields.add(f)
            fields.add(c.field)
        fields.add("id")  # always include id
        return list(fields)

    def callback_columns(self):
        return [c for c in self.columns if c.callbacks]
