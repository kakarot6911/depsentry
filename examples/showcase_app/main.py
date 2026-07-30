"""Application entrypoints.

Every handler below is an entrypoint, so anything they transitively call is
reachable. This is what makes the red paths in the 3D view real rather than
decorative.
"""

import config
import ingest
import model
import render


def main():
    settings = config.load_settings("settings.yaml")
    feed = ingest.fetch_feed(settings.get("feed_url", "https://example.com/feed"))
    frame = ingest.load_cached_frame(settings.get("cache", "cache.pkl"))
    clf = model.load_model(settings.get("model", "model.joblib"))
    scores = model.predict(clf, frame)
    return render.render_summary("{{ n }} scored", {"n": len(scores), "feed": feed})
