from django.apps import AppConfig
import pkgutil
import importlib

class InventoryConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "inventory"

    def ready(self):
        from . import tables  # inventory.tables package
        for m in pkgutil.iter_modules(tables.__path__):
            importlib.import_module(f"{tables.__name__}.{m.name}")