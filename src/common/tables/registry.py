# common/tables/registry.py

TABLE_REGISTRY = {}

def register_table(cls):
    key = f"{cls.table_group}:{cls.table_id}"
    TABLE_REGISTRY[key] = cls
    return cls

def get_table(group: str, table_id: str):
    return TABLE_REGISTRY.get(f"{group}:{table_id}")
