"""Upstream data ingestion. Both vulnerable symbols here ARE called."""

import requests
import pandas


def fetch_feed(url):
    # requests.get -- affected by the redirect header-leak advisory.
    return requests.get(url, timeout=10).json()


def load_cached_frame(path):
    # pandas.read_pickle -- affected by the untrusted-deserialisation advisory.
    return pandas.read_pickle(path)
