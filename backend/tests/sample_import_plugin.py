from backend.plugins.base import ControlsImportPlugin


class SampleImportPlugin(ControlsImportPlugin):
    plugin_id = "sample-import-plugin"
    display_name = "Sample Import Plugin"
    version = "1.2.3"
    config_schema = {
        "fields": {
            "file_path": {"type": "string", "required": True},
            "dry_run": {"type": "boolean", "default": False},
        }
    }

    def run(self):
        return []
