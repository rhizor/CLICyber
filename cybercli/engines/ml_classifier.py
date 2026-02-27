"""Machine‑learning based risk classifier.

This module implements a simple classifier for predicting the risk level of
a host based on its open ports.  While real deployments would leverage
feature engineering and training data derived from threat intelligence feeds
and past incidents, this implementation demonstrates how to integrate
scikit‑learn models into the CLI.  It supports training on arbitrary
features, saving/loading the model to disk, and making predictions.

The classifier uses a multinomial logistic regression model by default,
trained on synthetic data if no training dataset is provided.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Tuple, Union

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

from .blue_team import PORT_VULN_MAP


# Define a set of high‑risk ports based on Blue Team mappings
HIGH_RISK_PORTS = set(PORT_VULN_MAP.keys())


def extract_features(open_ports: Iterable[int]) -> List[float]:
    """Compute feature vector from a list of open ports.

    The current feature set consists of:

    * Total number of open ports.
    * Number of high‑risk ports (as defined by ``PORT_VULN_MAP``).
    * Number of other ports.

    Args:
        open_ports: Iterable of port numbers.

    Returns:
        A list of floats representing the feature vector.
    """
    ports = list(open_ports)
    total = len(ports)
    high_risk = sum(1 for p in ports if p in HIGH_RISK_PORTS)
    other = total - high_risk
    return [float(total), float(high_risk), float(other)]


def train_classifier(X: List[List[float]], y: List[int]) -> LogisticRegression:
    """Train a multinomial logistic regression model.

    Args:
        X: List of feature vectors.
        y: List of integer labels corresponding to risk classes (0=Low,
           1=Medium, 2=High).

    Returns:
        The trained LogisticRegression model.
    """
    model = LogisticRegression(multi_class="multinomial", max_iter=500)
    model.fit(np.array(X), np.array(y))
    return model


def train_default_model(samples: int = 200) -> LogisticRegression:
    """Train a default model on randomly generated data.

    This helper function creates synthetic training data by sampling random
    port lists and assigning risk labels based on the count of high‑risk ports.
    It is intended for demonstration purposes only.

    Args:
        samples: Number of synthetic samples to generate.

    Returns:
        A trained LogisticRegression model.
    """
    rng = np.random.default_rng()
    X: List[List[float]] = []
    y: List[int] = []
    possible_ports = list(range(20, 9000))
    for _ in range(samples):
        # sample a random number of open ports (1–20)
        n_ports = int(rng.integers(1, 20))
        ports = rng.choice(possible_ports, size=n_ports, replace=False)
        features = extract_features(ports)
        # assign label: high risk if >= 3 high‑risk ports, medium if 1–2, low otherwise
        risk_count = int(features[1])
        if risk_count >= 3:
            label = 2
        elif risk_count >= 1:
            label = 1
        else:
            label = 0
        X.append(features)
        y.append(label)
    return train_classifier(X, y)


def save_model(model: LogisticRegression, path: Union[str, Path]) -> None:
    """Persist the model to disk using joblib."""
    joblib.dump(model, str(path))


def load_model(path: Union[str, Path]) -> LogisticRegression:
    """Load a persisted model from disk."""
    return joblib.load(str(path))


def predict(model: LogisticRegression, features: Iterable[float]) -> Tuple[int, float]:
    """Predict the risk class for a single feature vector.

    Args:
        model: Trained LogisticRegression model.
        features: Iterable of feature values.

    Returns:
        A tuple of (predicted_class, confidence) where predicted_class is one
        of 0 (Low), 1 (Medium) or 2 (High), and confidence is the highest
        probability among classes.
    """
    arr = np.array([list(features)], dtype=float)
    prob = model.predict_proba(arr)[0]
    pred = int(np.argmax(prob))
    return pred, float(np.max(prob))


def model_path() -> Path:
    """Return the default path for storing the ML model in the user's config directory."""
    config_dir = Path(os.path.expanduser("~/.cybercli"))
    return config_dir / "risk_classifier.joblib"


__all__ = [
    "extract_features",
    "train_classifier",
    "train_default_model",
    "save_model",
    "load_model",
    "predict",
    "model_path",
]