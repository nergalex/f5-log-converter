import json
from pathlib import Path


class Configuration (object):
    def __init__(self, backup_file):
        self.file = backup_file
        self.config_json = None
        self.load()

    def load(self):
        if Path(self.file).is_file():
            self.config_json = json.load(open(self.file, mode='r'))

    def save(self):
        self.config_json = json.dump(
            self.config_json,
            open(self.file, mode='w+t'),
            sort_keys=True,
            indent=4,
            ensure_ascii=False
        )

    def get_json(self):
        return self.config_json

    def set_json(self, config_json):
        self.config_json = config_json
