import os
import numpy as np
from typing import List, Dict, Any
from collections import deque

class LSTMDetector:
    def __init__(self, model_path=None, sequence_window=10):
        self.model = None
        self.model_path = model_path or "./models/lstm_detector.pkl"
        self.sequence_window = sequence_window
        self.sequence_buffer = deque(maxlen=sequence_window)
        self.tf_available = False

        try:
            import tensorflow as tf
            from tensorflow.keras.models import Sequential
            from tensorflow.keras.layers import LSTM, Dense, Dropout
            self.tf = tf
            self.Sequential = Sequential
            self.LSTM = LSTM
            self.Dense = Dense
            self.Dropout = Dropout
            self.tf_available = True
        except ImportError:
            pass

        self.load_or_init()

    def load_or_init(self):
        if os.path.exists(self.model_path) and self.tf_available:
            self.model = self.tf.keras.models.load_model(self.model_path)
            self._is_trained = True
        elif self.tf_available:
            self._build_model()
            # A freshly-built Keras model has random initial weights and
            # won't raise on .predict() - it'll just silently return
            # meaningless output that looks like a real score. Previously
            # nothing distinguished "loaded a trained model" from "built an
            # untrained one moments ago", so an un-trained deployment would
            # report confident-looking sequence scores that meant nothing.
            self._is_trained = False
        else:
            self.model = None
            self._is_trained = False

    def _build_model(self, input_dim=53):
        model = self.Sequential([
            self.LSTM(64, return_sequences=True, input_shape=(self.sequence_window, input_dim)),
            self.Dropout(0.2),
            self.LSTM(32),
            self.Dropout(0.2),
            self.Dense(16, activation="relu"),
            self.Dense(1, activation="sigmoid")
        ])
        model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
        self.model = model

    def fit(self, X: np.ndarray, y: np.ndarray, epochs=10, batch_size=32):
        if not self.tf_available or self.model is None:
            return
        self.model.fit(X, y, epochs=epochs, batch_size=batch_size, verbose=0)
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        self.model.save(self.model_path)
        self._is_trained = True

    def update_sequence(self, feature_vector: List[float]):
        self.sequence_buffer.append(feature_vector)

    def is_trained(self) -> bool:
        return bool(self._is_trained)

    def detect(self) -> float:
        use_model = self.tf_available and self.model is not None and self._is_trained and len(self.sequence_buffer) >= self.sequence_window
        if not use_model:
            if len(self.sequence_buffer) < 2:
                return 0.0
            # Fallback heuristic used whenever there's no trained LSTM
            # (i.e. TensorFlow isn't installed, or scripts/train_models.py
            # hasn't produced a model yet - which is every default
            # install, since tensorflow isn't in requirements.txt and
            # models/ ships without an lstm_detector file).
            #
            # This previously computed variance WITHIN a single feature
            # vector (across ~55 features of wildly different scales -
            # duration ~0-100, byte counts in the thousands...), which
            # measures nothing temporal at all - a "sequence" score that
            # was really just "which feature happens to have the largest
            # raw units this flow". Now it measures variance ACROSS
            # timesteps, per feature dimension, which is at least
            # directionally the right thing (an unstable/bursty feature
            # profile over time vs. a flat one) even without a trained
            # model. It's still an unscaled heuristic, not a real
            # sequence model - ThreatScorer treats it as lower-confidence
            # accordingly (see is_trained()).
            recent = np.array(list(self.sequence_buffer)[-5:], dtype=float)
            if recent.shape[0] < 2:
                return 0.0
            per_feature_temporal_variance = np.var(recent, axis=0)
            return float(min(1.0, np.mean(per_feature_temporal_variance) * 10))

        sequence = np.array([list(self.sequence_buffer)])
        prediction = self.model.predict(sequence, verbose=0)
        return float(prediction[0][0])
