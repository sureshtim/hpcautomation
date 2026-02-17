# common/tables/columns.py

class BaseColumn:
    def __init__(self, **kwargs):
        self.field = None
        self.title = None
        self.frozen = False
        self.hozAlign = "left"
        self.editable = False
        self.editor = "input"
        self.formatter = None
        self.formatterParams = {}
        self.editorParams = {}
        self.callbacks = {}
        self.visible = True
        self.__dict__.update(kwargs)

    def to_tabulator(self, can_edit_table: bool):
        col = {
            "title": self.title,
            "field": self.field,
        }
        if self.frozen:
            col["frozen"] = True
        if self.hozAlign:
            col["hozAlign"] = self.hozAlign
        if self.formatter:
            col["formatter"] = self.formatter
        if self.formatterParams:
            col["formatterParams"] = self.formatterParams

        # only add editor if editable and user has table edit permission
        if self.editable and can_edit_table:
            col["editor"] = self.editor
            if self.editorParams:
                col["editorParams"] = self.editorParams

        return col


class Column(BaseColumn):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class TextAreaColumn(BaseColumn):
    def __init__(self, **kwargs):
        kwargs.setdefault("formatter", "textarea")
        super().__init__(**kwargs)


class TimeColumn(BaseColumn):
    def __init__(self, **kwargs):
        # you can format on frontend too; keep here for consistency
        kwargs.setdefault("formatter", "datetime")
        super().__init__(**kwargs)
