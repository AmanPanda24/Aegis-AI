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
        elif self.tf_available:
            self._build_model()
        else:
            self.model = None

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

    def update_sequence(self, feature_vector: List[float]):
        self.sequence_buffer.append(feature_vector)

    def detect(self) -> float:
        if not self.tf_available or self.model is None or len(self.sequence_buffer) < self.sequence_window:
            if len(self.sequence_buffer) < 2:
                return 0.0
            recent = list(self.sequence_buffer)[-5:]
            variances = [np.var(f) for f in recent]
            return float(min(1.0, np.mean(variances) * 10))

        sequence = np.array([list(self.sequence_buffer)])
        prediction = self.model.predict(sequence, verbose=0)
        return float(prediction[0][0])
