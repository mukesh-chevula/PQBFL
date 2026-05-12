"""
ai/detector.py
AI Anomaly Detector — Saeed & Alqahtani (2024) §V.

A Random Forest classifier trained on timing-trace features to distinguish
benign IoT operations from side-channel probing attacks.

Saeed & Alqahtani report:
  • Accuracy   ≥ 98.2% on their test set
  • F1-score   ≥ 0.981
  • False-positive rate < 0.8%

We reproduce comparable performance on our synthetic traces.

Two key insights from the paper:
  1. VULNERABLE implementations show HIGH feature separability
     (std, range, skewness all differ markedly between benign/attack).
  2. HARDENED implementations show LOW separability — the AI detector
     CANNOT reliably distinguish attack from benign when the implementation
     is constant-time, confirming hardening effectiveness.

This is the central experimental claim of Saeed & Alqahtani (2024) and
the reason JOURNAL-3 adopts constant-time HMAC comparison and CSPRNG nonces.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    confusion_matrix, roc_auc_score,
)
from sklearn.model_selection import train_test_split

from saeed2024.ai.feature_extractor import build_feature_matrix, FEATURE_NAMES
from saeed2024.attacks.timing_leakage import TimingObservation, LeakageMode


@dataclass
class DetectorMetrics:
    accuracy:     float
    precision:    float
    recall:       float
    f1:           float
    auc_roc:      float
    fpr:          float    # false positive rate
    fnr:          float    # false negative rate
    confusion:    list     # [[TN, FP], [FN, TP]]
    mode:         str
    n_train:      int
    n_test:       int
    feature_importances: list  # top 5 features


class SideChannelDetector:
    """
    Random Forest classifier for side-channel attack detection.

    Trained on statistical features of timing traces from an IoT device.
    Can be evaluated on both VULNERABLE and HARDENED device implementations
    to demonstrate how hardening degrades attacker signal (and detector lift).
    """

    def __init__(
        self,
        n_estimators: int   = 100,
        max_depth:    int   = 12,
        window_size:  int   = 20,
        step:         int   = 10,
        seed:         int   = 42,
    ):
        self.window_size = window_size
        self.step        = step
        self.seed        = seed
        self._clf  = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=seed,
            n_jobs=-1,
        )
        self._scaler = StandardScaler()
        self._trained = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, observations: list[TimingObservation]) -> DetectorMetrics:
        """
        Extract features from observations, split, train, and evaluate.

        Returns DetectorMetrics on the held-out test set.
        """
        timings = [o.measured_us for o in observations]
        labels  = [1 if o.is_attack else 0 for o in observations]
        mode    = observations[0].mode.name if observations else "UNKNOWN"

        X, y = build_feature_matrix(timings, labels, self.window_size, self.step)

        if len(X) < 10:
            raise ValueError("Not enough windows to train. Increase n_samples.")

        try:
            X_tr, X_te, y_tr, y_te = train_test_split(
                X, y, test_size=0.25, stratify=y, random_state=self.seed
            )
        except ValueError:
            X_tr, X_te, y_tr, y_te = train_test_split(
                X, y, test_size=0.25, random_state=self.seed
            )

        X_tr_s = self._scaler.fit_transform(X_tr)
        X_te_s = self._scaler.transform(X_te)

        self._clf.fit(X_tr_s, y_tr)
        self._trained = True

        y_pred = self._clf.predict(X_te_s)
        y_prob = self._clf.predict_proba(X_te_s)[:, 1]

        cm   = confusion_matrix(y_te, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, len(y_te))
        fpr  = fp / (fp + tn + 1e-9)
        fnr  = fn / (fn + tp + 1e-9)

        # Feature importances — top 5
        imp  = self._clf.feature_importances_
        top5 = sorted(zip(FEATURE_NAMES, imp), key=lambda x: -x[1])[:5]

        return DetectorMetrics(
            accuracy  = round(float(accuracy_score(y_te, y_pred)), 4),
            precision = round(float(precision_score(y_te, y_pred, zero_division=0)), 4),
            recall    = round(float(recall_score(y_te, y_pred, zero_division=0)), 4),
            f1        = round(float(f1_score(y_te, y_pred, zero_division=0)), 4),
            auc_roc   = round(float(roc_auc_score(y_te, y_prob)), 4),
            fpr       = round(float(fpr), 4),
            fnr       = round(float(fnr), 4),
            confusion = cm.tolist(),
            mode      = mode,
            n_train   = len(X_tr),
            n_test    = len(X_te),
            feature_importances = [(n, round(float(v), 4)) for n, v in top5],
        )

    def predict(self, observations: list[TimingObservation]) -> np.ndarray:
        """Predict attack / benign on new observations."""
        if not self._trained:
            raise RuntimeError("Call fit() first.")
        timings = [o.measured_us for o in observations]
        labels  = [0] * len(timings)
        X, _ = build_feature_matrix(timings, labels, self.window_size, self.step)
        X_s  = self._scaler.transform(X)
        return self._clf.predict(X_s)

    def predict_proba(self, observations: list[TimingObservation]) -> np.ndarray:
        """Return attack probability per window."""
        if not self._trained:
            raise RuntimeError("Call fit() first.")
        timings = [o.measured_us for o in observations]
        labels  = [0] * len(timings)
        X, _ = build_feature_matrix(timings, labels, self.window_size, self.step)
        X_s  = self._scaler.transform(X)
        return self._clf.predict_proba(X_s)[:, 1]
