"""Model loading -- joblib.load is on a live path from the predict endpoint."""

import joblib
import numpy


def load_model(path):
    return joblib.load(path)


def predict(model, rows):
    return model.predict(numpy.array(rows))
