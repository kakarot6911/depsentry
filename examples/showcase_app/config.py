"""Configuration loading.

Uses the SAFE loader deliberately. The advisory on `yaml.load` (CVSS 9.8, RCE)
matches this pinned PyYAML version, but the vulnerable symbol is never called --
so DepSentry should suppress it while a conventional scanner fails the build.
"""

import yaml


def load_settings(path):
    with open(path) as handle:
        return yaml.safe_load(handle)
