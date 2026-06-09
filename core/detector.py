"""Anomaly detection module for eBPF-Shield.

Wraps scikit-learn's IsolationForest behind a simple train / load / predict
API.  Feature vectors are first normalised with a ``StandardScaler`` and
persisted alongside the model via ``joblib``.

Uses a **hybrid approach**: heuristic rules for known-bad patterns
(privilege escalation, shell spawn, ransomware, lateral movement, C2, etc.)
combined with ML anomaly scoring for unknown/novel attacks.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import FrozenSet, List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from core.feature_extractor import FeatureVector, FEATURE_NAMES


class AnomalyDetector:
    """Hybrid anomaly detector: heuristic rules + IsolationForest.

    Detection is triggered if ANY of the following is true:
    1. **Heuristic rules** flag known-bad patterns (priv escalation,
       ransomware, lateral movement, fileless malware, C2, etc.)
    2. **ML score** from IsolationForest falls below ``threshold``

    Args:
        contamination: Expected proportion of anomalies in training data.
        model_path: File path used to persist the trained IsolationForest.
        scaler_path: File path used to persist the fitted StandardScaler.
        threshold: Decision-function threshold below which a sample is
            considered anomalous (default ``-0.1``).
    """

    def __init__(
        self,
        contamination: float = 0.05,
        model_path: str = "data/baseline_model.pkl",
        scaler_path: str = "data/scaler.pkl",
        threshold: float = -0.1,
    ) -> None:
        self.contamination: float = contamination
        self.model_path: str = model_path
        self.scaler_path: str = scaler_path
        self.threshold: float = threshold

        self._model: IsolationForest | None = None
        self._scaler: StandardScaler | None = None
        self._markov_matrix: dict | None = None
        self._stale_model: bool = False

        # Adversarial robustness settings
        self._feature_min: FrozenSet[float] = frozenset({0.0})
        self._feature_max: FrozenSet[float] = frozenset({10000.0})
        
        # Sequence model threshold (1% transition probability)
        self.seq_threshold = 0.01

    # ------------------------------------------------------------------ #
    # Training                                                            #
    # ------------------------------------------------------------------ #
    def train(self, feature_vectors: list[FeatureVector]) -> None:
        """Fit the scaler and IsolationForest on *feature_vectors*.

        After training the model and scaler are saved to disk at the paths
        specified during construction.

        Args:
            feature_vectors: A list of :class:`FeatureVector` instances
                representing *normal* baseline behaviour.

        Raises:
            ValueError: If *feature_vectors* is empty.
        """
        if not feature_vectors:
            raise ValueError("Cannot train on an empty list of feature vectors.")

        # Build (n_samples, n_features) matrix.
        X = np.vstack([fv.features for fv in feature_vectors])

        # Validate and sanitize features before training
        X = self._sanitize_features(X)

        # Fit scaler.
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Fit IsolationForest.
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self._model.fit(X_scaled)

        # Train Markov Chain (Bigram)
        transitions = {}
        for fv in feature_vectors:
            seq = getattr(fv, 'syscall_sequence', [])
            for i in range(len(seq) - 1):
                pair = (seq[i], seq[i+1])
                transitions[pair] = transitions.get(pair, 0) + 1
                
        # Normalize probabilities
        self._markov_matrix = {}
        for i in range(16): # 16 monitored syscall types
            total = sum(v for k, v in transitions.items() if k[0] == i)
            if total > 0:
                for j in range(16):
                    self._markov_matrix[(i, j)] = transitions.get((i, j), 0) / total

        # Persist to disk.
        self._save()

    # ------------------------------------------------------------------ #
    # Persistence                                                         #
    # ------------------------------------------------------------------ #
    def _save(self) -> None:
        """Serialise model and scaler to disk via joblib."""
        for path in (self.model_path, self.scaler_path):
            parent = Path(path).parent
            if parent and not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)

        joblib.dump(self._model, self.model_path)
        joblib.dump(self._scaler, self.scaler_path)
        
        markov_path = str(self.model_path).replace(".pkl", "_markov.pkl")
        joblib.dump(self._markov_matrix, markov_path)

    def load(self) -> None:
        """Load a previously trained model and scaler from disk.

        Raises:
            FileNotFoundError: If the model or scaler file does not exist.
        """
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model file not found at '{self.model_path}'. "
                "Please train the model first with detector.train(...)."
            )
        if not os.path.exists(self.scaler_path):
            raise FileNotFoundError(
                f"Scaler file not found at '{self.scaler_path}'. "
                "Please train the model first with detector.train(...)."
            )

        self._model = joblib.load(self.model_path)
        self._scaler = joblib.load(self.scaler_path)
        
        markov_path = str(self.model_path).replace(".pkl", "_markov.pkl")
        if os.path.exists(markov_path):
            self._markov_matrix = joblib.load(markov_path)
        else:
            self._markov_matrix = {}

        # Validate feature count against current FEATURE_NAMES
        expected_current = len(FEATURE_NAMES)
        scaler_n_features = getattr(self._scaler, "n_features_in_", None)
        
        # Fallback for older scikit-learn or if attribute missing
        if scaler_n_features is None and hasattr(self._scaler, "mean_"):
             scaler_n_features = len(self._scaler.mean_)

        if scaler_n_features is not None and scaler_n_features != expected_current:
            import warnings
            warnings.warn(
                f"Loaded model expects {scaler_n_features} features, but "
                f"the current code produces {expected_current}. "
                f"ML scoring will use only the first {scaler_n_features} features. "
                f"Retrain with 'sudo python3 main.py train' to use all features.",
                stacklevel=2,
            )
            self._stale_model = True
        else:
            self._stale_model = False

    # ------------------------------------------------------------------ #
    # Feature sanitization (adversarial robustness)                       #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _sanitize_features(X: np.ndarray) -> np.ndarray:
        """Sanitize features to prevent adversarial manipulation.

        - Replaces NaN/Inf with 0
        - Clamps negative values to 0
        - Clamps values to reasonable maximums

        Args:
            X: Feature matrix.

        Returns:
            Sanitized feature matrix.
        """
        X = np.copy(X)

        # Replace NaN/Inf with 0
        X = np.where(np.isfinite(X), X, 0.0)

        # Clamp negative values to 0 (features can't be negative)
        X = np.maximum(X, 0.0)

        # Define reasonable max values for each feature
        max_values = [
            10000.0, 16.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0,
            100000.0, 100000.0, 1000.0, 1000.0, 1000.0, 100.0, 100.0, 100.0,
            1000.0, 1000.0, 1000.0, 1000.0, 1000.0, 100.0, 100.0, 100.0,
            100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0,
        ]

        # Clamp each feature to its max
        for i in range(min(X.shape[1], len(max_values))):
            X[:, i] = np.minimum(X[:, i], max_values[i])

        return X

    @staticmethod
    def validate_feature_vector(fv: FeatureVector) -> Tuple[bool, str]:
        """Validate a feature vector for adversarial manipulation.

        Args:
            fv: FeatureVector to validate.

        Returns:
            Tuple of (is_valid, error_message).
        """
        features = fv.features

        # Check for NaN/Inf
        if not np.all(np.isfinite(features)):
            return False, "Feature vector contains NaN or Inf values"

        # Check for negative values
        if np.any(features < 0):
            return False, "Feature vector contains negative values"

        # Check feature count matches FEATURE_NAMES
        if len(features) != len(FEATURE_NAMES):
            return False, f"Feature count mismatch: expected {len(FEATURE_NAMES)}, got {len(features)}"

        return True, ""

    # ------------------------------------------------------------------ #
    # Heuristic rules                                                     #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _check_heuristics(fv: FeatureVector) -> List[str]:
        """Check feature vector against known-bad heuristic patterns.

        Returns a list of triggered rule descriptions (empty if clean).
        """
        f = fv.features
        triggered: List[str] = []

        # Feature indices (from FEATURE_NAMES):
        #  0=syscall_count, 1=unique_syscalls
        #  2=execve_count, 3=openat_count, 4=connect_count
        #  5=ptrace_count, 6=setuid_count, 7=clone_count, 8=write_count
        #  9=syscall_rate, 10=sensitive_file_access
        # 11=shell_spawn, 12=uid_change_attempt
        # 13=syscall_entropy, 14=priv_esc_sequence
        # 15=memprotect_rx_count, 16=anonymous_mmap_count
        # 17=fd_based_exec_count, 18=memory_region_toggle_count
        # 19=fileless_score, 20=fileless_exec
        # 21=unique_file_opens, 22=write_to_new_files
        # 23=delete_operations, 24=file_extension_diversity
        # 25=ransom_note_pattern, 26=ransomware_score
        # 27=ssh_remote_exec, 28=credential_access_count
        # 29=port_scan_count, 30=lateral_movement_score
        # 31=beacon_periodicity, 32=non_standard_port_count

        # === Original rules (0-14) ===
        ptrace_count = f[5]
        setuid_count = f[6]
        sensitive_file = f[10]
        shell_spawn = f[11]
        uid_change = f[12]
        priv_esc_seq = f[14]
        connect_count = f[4]

        # Rule 1: Privilege escalation sequence (ptrace->setuid or setuid->execve)
        if priv_esc_seq >= 1.0:
            triggered.append("priv_esc_sequence")

        # Rule 2: Shell spawn + UID change attempt
        if shell_spawn > 0 and uid_change >= 1.0:
            triggered.append("shell_spawn + uid_change")

        # Rule 3: ptrace usage (very rare in normal workloads, but allow single attach)
        if ptrace_count >= 2:
            triggered.append(f"ptrace({int(ptrace_count)}x)")

        # Rule 4: setuid + shell spawn (without full sequence detection)
        if setuid_count > 0 and shell_spawn > 0:
            triggered.append("setuid + shell_spawn")

        # Rule 5: Sensitive file access — only flag if substantial (≥3 accesses)
        # Single accesses to /etc/passwd are common for user lookups
        if sensitive_file >= 3:
            triggered.append(f"sensitive_file_access({int(sensitive_file)}x)")

        # Rule 6: Sensitive file access + uid change
        if sensitive_file > 0 and uid_change >= 1.0:
            triggered.append("sensitive_file + uid_change")

        # Rule 7: Reverse Shell pattern (Network Connection + Shell Spawn)
        if connect_count > 0 and shell_spawn > 0:
            triggered.append("reverse_shell")

        # Rule 8: Fileless Malware Execution (original check)
        if fv.fileless_exec:
            triggered.append("fileless_malware_execution")

        # === Fileless malware rules (15-20) ===
        memprotect_rx = f[15]
        anonymous_mmap = f[16]
        fd_based_exec = f[17]
        memory_toggle = f[18]
        fileless_score = f[19]
        fileless_exec = f[20]

        # Rule 9: mprotect PROT_EXEC (memory permission change to executable)
        if memprotect_rx >= 2.0:
            triggered.append(f"mprotect_rx({int(memprotect_rx)}x)")

        # Rule 10: Anonymous mmap (allocating anonymous memory — normal programs do a few)
        if anonymous_mmap >= 5.0:
            triggered.append(f"anonymous_mmap({int(anonymous_mmap)}x)")

        # Rule 11: fd-based execution (execveat with file descriptor)
        if fd_based_exec >= 1.0:
            triggered.append("fd_based_exec")

        # Rule 12: Memory region toggling (write -> mprotect RX pattern)
        if memory_toggle >= 1.0:
            triggered.append("memory_region_toggle")

        # Rule 13: Combined fileless score heuristic
        if fileless_score >= 0.7:
            triggered.append(f"fileless_score({fileless_score:.2f})")

        # Rule 14: Explicit fileless exec flag
        if fileless_exec >= 1.0:
            triggered.append("fileless_malware_execution")

        # === Ransomware rules (21-26) ===
        unique_file_opens = f[21]
        write_new_files = f[22]
        delete_ops = f[23]
        file_ext_div = f[24]
        ransom_note = f[25]
        ransomware_score = f[26]

        # Rule 15: Mass file encryption pattern
        if unique_file_opens >= 50:
            triggered.append(f"mass_file_access({int(unique_file_opens)} files)")

        # Rule 16: Writing to many new files
        if write_new_files >= 30:
            triggered.append(f"mass_file_write({int(write_new_files)} files)")

        # Rule 17: Rapid file deletion
        if delete_ops >= 20:
            triggered.append(f"rapid_file_delete({int(delete_ops)} ops)")

        # Rule 18: Ransom note dropped
        if ransom_note >= 1.0:
            triggered.append("ransom_note_dropped")

        # Rule 19: Combined ransomware score
        if ransomware_score >= 0.8:
            triggered.append(f"ransomware_score({ransomware_score:.2f})")

        # === Lateral movement rules (27-30) ===
        ssh_remote = f[27]
        credential_access = f[28]
        port_scan = f[29]
        lateral_score = f[30]

        # Rule 20: SSH remote execution
        if ssh_remote >= 1.0:
            triggered.append(f"ssh_remote_exec({int(ssh_remote)}x)")

        # Rule 21: Credential dumping (single reads can be innocent, need pattern)
        if credential_access >= 2.0:
            triggered.append(f"credential_access({int(credential_access)}x)")

        # Rule 22: Port scanning behavior
        if port_scan >= 10.0:
            triggered.append(f"port_scan({int(port_scan)} ports)")

        # Rule 23: Combined lateral movement score
        if lateral_score >= 0.7:
            triggered.append(f"lateral_movement_score({lateral_score:.2f})")

        # === C2 communication rules (31-32) ===
        beacon_periodicity = f[31]
        non_std_port = f[32]

        # Rule 24: Beaconing C2 (regular connection intervals)
        # beacon_periodicity is normalized variance - low = regular = suspicious
        if beacon_periodicity < 0.1 and connect_count >= 3:
            triggered.append(f"beaconing_c2(variance={beacon_periodicity:.3f})")

        # Rule 25: Non-standard port C2
        if non_std_port >= 1.0:
            triggered.append(f"non_standard_port_c2({int(non_std_port)}x)")

        # Rule 26: Reverse shell + non-standard port combo
        if shell_spawn > 0 and non_std_port > 0:
            triggered.append("reverse_shell_non_std_port")

        return triggered

    # ------------------------------------------------------------------ #
    # Prediction                                                          #
    # ------------------------------------------------------------------ #
    def predict(self, fv: FeatureVector) -> Tuple[bool, float, str]:
        """Score a single feature vector using hybrid detection.

        Checks heuristic rules first (instant detection of known-bad
        patterns), then falls back to the ML anomaly score.

        Args:
            fv: The :class:`FeatureVector` to evaluate.

        Returns:
            A ``(is_anomaly, score, reason)`` tuple.
            - ``is_anomaly``: ``True`` if the feature vector is suspicious.
            - ``score``: Raw IsolationForest decision-function score.
            - ``reason``: Human-readable explanation of why it was flagged.

        Raises:
            RuntimeError: If neither :meth:`train` nor :meth:`load` has been
                called yet.
        """
        if self._model is None or self._scaler is None:
            raise RuntimeError(
                "Detector is not ready. Call train() or load() first."
            )

        # Step 0: Validate feature vector
        is_valid, error_msg = self.validate_feature_vector(fv)
        if not is_valid:
            raise ValueError(f"Invalid feature vector: {error_msg}")

        # Step 1: Check heuristic rules
        heuristic_hits = self._check_heuristics(fv)

        # Step 2: Sanitize features before ML scoring
        features = self._sanitize_features(fv.features.reshape(1, -1))

        # Step 3: Get ML score (handle stale models with fewer features)
        scaler_n = getattr(self._scaler, "n_features_in_", None)
        if scaler_n is None and hasattr(self._scaler, "mean_"):
             scaler_n = len(self._scaler.mean_)
             
        if scaler_n and features.shape[1] > scaler_n:
            # Slice to only the features the saved scaler knows about
            ml_features = features[:, :scaler_n]
        elif scaler_n and features.shape[1] < scaler_n:
            # Should not happen normally, but pad with zeros if needed
            ml_features = np.pad(features, ((0, 0), (0, scaler_n - features.shape[1])), mode='constant')
        else:
            ml_features = features
            
        X_scaled = self._scaler.transform(ml_features)
        raw_score: float = float(self._model.decision_function(X_scaled)[0])

        # Step 4: Sequence Analysis (Markov Chain)
        seq_anomaly = False
        min_prob = 1.0
        seq = getattr(fv, 'syscall_sequence', [])
        if len(seq) > 1 and self._markov_matrix:
            for i in range(len(seq) - 1):
                prob = self._markov_matrix.get((seq[i], seq[i+1]), 0.0)
                if prob < min_prob:
                    min_prob = prob
                if prob < self.seq_threshold:
                    seq_anomaly = True
                    break

        # Step 5: Decide
        ml_anomaly: bool = raw_score < self.threshold
        heuristic_anomaly: bool = len(heuristic_hits) > 0

        is_anomaly = ml_anomaly or heuristic_anomaly or seq_anomaly

        # Build reason string
        reasons: List[str] = []
        if heuristic_hits:
            reasons.append("RULES: " + ", ".join(heuristic_hits))
        if ml_anomaly:
            reasons.append(f"ML: score={raw_score:.3f}")
        if seq_anomaly:
            reasons.append(f"SEQ: prob={min_prob:.4f}")

        reason = " | ".join(reasons) if reasons else "normal"

        return is_anomaly, raw_score, reason

    # ------------------------------------------------------------------ #
    # Ensemble detection (adversarial robustness)                         #
    # ------------------------------------------------------------------ #
    def predict_with_confidence(self, fv: FeatureVector) -> Tuple[bool, float, str, float]:
        """Score a feature vector with ensemble confidence.

        Args:
            fv: The FeatureVector to evaluate.

        Returns:
            Tuple of (is_anomaly, score, reason, confidence).
            - confidence: 0.0 to 1.0, based on heuristic agreement.
        """
        is_anomaly, score, reason = self.predict(fv)

        # Calculate confidence based on heuristic agreement
        heuristic_hits = self._check_heuristics(fv)
        num_heuristics = len(heuristic_hits)

        # More heuristics triggered = higher confidence
        confidence = min(num_heuristics / 5.0, 1.0)  # 5+ heuristics = 100% confidence

        # If ML strongly agrees, boost confidence
        if score < self.threshold - 0.5:
            confidence = max(confidence, 0.8)

        return is_anomaly, score, reason, confidence
