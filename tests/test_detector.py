"""Unit tests for :mod:`core.detector`.

All tests are Windows-safe — models are stored in pytest's ``tmp_path``
fixture rather than at a hard-coded Linux path.
"""

from __future__ import annotations

import numpy as np
import pytest

from core.detector import AnomalyDetector
from core.feature_extractor import FEATURE_NAMES, FeatureVector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_fv(features: list[float] | np.ndarray, pid: int = 1000) -> FeatureVector:
    """Build a :class:`FeatureVector` from a raw feature list."""
    arr = np.array(features, dtype=np.float64)
    return FeatureVector(
        pid=pid,
        comm="test",
        timestamp=0.0,
        features=arr,
        feature_names=list(FEATURE_NAMES),
    )


def _normal_features(rng: np.random.Generator) -> list[float]:
    """Produce a 33-element feature list that looks 'normal'.

    Low ptrace/setuid/shell_spawn, moderate file I/O.
    """
    return [
        rng.integers(5, 50),       # 0: syscall_count
        rng.integers(2, 5),        # 1: unique_syscalls
        0.0,                        # 2: execve_count
        rng.integers(1, 10),       # 3: openat_count
        rng.integers(0, 3),        # 4: connect_count
        0.0,                        # 5: ptrace_count
        0.0,                        # 6: setuid_count
        rng.integers(0, 2),        # 7: clone_count
        rng.integers(5, 30),       # 8: write_count
        rng.uniform(1.0, 10.0),    # 9: syscall_rate
        0.0,                        # 10: sensitive_file_access
        0.0,                        # 11: shell_spawn
        0.0,                        # 12: uid_change_attempt
        rng.uniform(0.5, 2.0),     # 13: syscall_entropy
        0.0,                        # 14: priv_esc_sequence
        # Fileless (15-20)
        0.0,                        # 15: memprotect_rx_count
        0.0,                        # 16: anonymous_mmap_count
        0.0,                        # 17: fd_based_exec_count
        0.0,                        # 18: memory_region_toggle_count
        0.0,                        # 19: fileless_score
        0.0,                        # 20: fileless_exec
        # Ransomware (21-26)
        rng.integers(0, 10),      # 21: unique_file_opens
        0.0,                        # 22: write_to_new_files
        0.0,                        # 23: delete_operations
        0.0,                        # 24: file_extension_diversity
        0.0,                        # 25: ransom_note_pattern
        0.0,                        # 26: ransomware_score
        # Lateral movement (27-30)
        0.0,                        # 27: ssh_remote_exec
        0.0,                        # 28: credential_access_count
        0.0,                        # 29: port_scan_count
        0.0,                        # 30: lateral_movement_score
        # C2 (31-32)
        rng.uniform(0.5, 1.0),     # 31: beacon_periodicity
        0.0,                        # 32: non_standard_port_count
    ]


def _fileless_malware_features() -> list[float]:
    """Produce a 33-element feature list that indicates fileless malware."""
    return [
        100.0,  # 0: syscall_count (high)
        6.0,    # 1: unique_syscalls
        5.0,    # 2: execve_count
        10.0,   # 3: openat_count
        0.0,    # 4: connect_count
        0.0,    # 5: ptrace_count
        0.0,    # 6: setuid_count
        20.0,   # 7: clone_count
        50.0,   # 8: write_count
        500.0,  # 9: syscall_rate (extremely fast)
        0.0,    # 10: sensitive_file_access
        0.0,    # 11: shell_spawn
        0.0,    # 12: uid_change_attempt
        2.5,    # 13: syscall_entropy
        0.0,    # 14: priv_esc_sequence
        # Fileless (15-20)
        5.0,    # 15: memprotect_rx_count (high!)
        10.0,   # 16: anonymous_mmap_count (high!)
        2.0,    # 17: fd_based_exec_count
        3.0,    # 18: memory_region_toggle_count
        0.9,    # 19: fileless_score (high!)
        1.0,    # 20: fileless_exec
        # Ransomware (21-26)
        10.0,   # 21: unique_file_opens
        0.0,    # 22: write_to_new_files
        0.0,    # 23: delete_operations
        0.0,    # 24: file_extension_diversity
        0.0,    # 25: ransom_note_pattern
        0.0,    # 26: ransomware_score
        # Lateral movement (27-30)
        0.0,    # 27: ssh_remote_exec
        0.0,    # 28: credential_access_count
        0.0,    # 29: port_scan_count
        0.0,    # 30: lateral_movement_score
        # C2 (31-32)
        0.8,    # 31: beacon_periodicity
        0.0,    # 32: non_standard_port_count
    ]


def _ransomware_features() -> list[float]:
    """Produce a 33-element feature list that indicates ransomware."""
    return [
        500.0,  # 0: syscall_count (very high)
        5.0,    # 1: unique_syscalls
        1.0,    # 2: execve_count
        200.0,  # 3: openat_count (mass file access!)
        0.0,    # 4: connect_count
        0.0,    # 5: ptrace_count
        0.0,    # 6: setuid_count
        10.0,   # 7: clone_count
        300.0,  # 8: write_count
        1000.0, # 9: syscall_rate (extremely fast)
        0.0,    # 10: sensitive_file_access
        0.0,    # 11: shell_spawn
        0.0,    # 12: uid_change_attempt
        2.0,    # 13: syscall_entropy
        0.0,    # 14: priv_esc_sequence
        # Fileless (15-20)
        0.0,    # 15: memprotect_rx_count
        0.0,    # 16: anonymous_mmap_count
        0.0,    # 17: fd_based_exec_count
        0.0,    # 18: memory_region_toggle_count
        0.0,    # 19: fileless_score
        0.0,    # 20: fileless_exec
        # Ransomware (21-26)
        100.0,  # 21: unique_file_opens (mass!)
        80.0,   # 22: write_to_new_files (mass!)
        50.0,   # 23: delete_operations (mass!)
        3.5,    # 24: file_extension_diversity
        1.0,    # 25: ransom_note_pattern (ransom note!)
        0.95,   # 26: ransomware_score (very high!)
        # Lateral movement (27-30)
        0.0,    # 27: ssh_remote_exec
        0.0,    # 28: credential_access_count
        0.0,    # 29: port_scan_count
        0.0,    # 30: lateral_movement_score
        # C2 (31-32)
        0.8,    # 31: beacon_periodicity
        0.0,    # 32: non_standard_port_count
    ]


def _lateral_movement_features() -> list[float]:
    """Produce a 33-element feature list that indicates lateral movement."""
    return [
        50.0,   # 0: syscall_count
        4.0,    # 1: unique_syscalls
        5.0,    # 2: execve_count (ssh invocations)
        20.0,   # 3: openat_count
        10.0,   # 4: connect_count
        0.0,    # 5: ptrace_count
        0.0,    # 6: setuid_count
        5.0,    # 7: clone_count
        10.0,   # 8: write_count
        50.0,   # 9: syscall_rate
        5.0,    # 10: sensitive_file_access (SSH keys)
        0.0,    # 11: shell_spawn
        0.0,    # 12: uid_change_attempt
        2.0,    # 13: syscall_entropy
        0.0,    # 14: priv_esc_sequence
        # Fileless (15-20)
        0.0,    # 15: memprotect_rx_count
        0.0,    # 16: anonymous_mmap_count
        0.0,    # 17: fd_based_exec_count
        0.0,    # 18: memory_region_toggle_count
        0.0,    # 19: fileless_score
        0.0,    # 20: fileless_exec
        # Ransomware (21-26)
        20.0,   # 21: unique_file_opens
        0.0,    # 22: write_to_new_files
        0.0,    # 23: delete_operations
        0.0,    # 24: file_extension_diversity
        0.0,    # 25: ransom_note_pattern
        0.0,    # 26: ransomware_score
        # Lateral movement (27-30)
        5.0,    # 27: ssh_remote_exec (SSH invocations!)
        3.0,    # 28: credential_access_count (SSH key access!)
        0.0,    # 29: port_scan_count
        0.9,    # 30: lateral_movement_score (very high!)
        # C2 (31-32)
        0.8,    # 31: beacon_periodicity
        0.0,    # 32: non_standard_port_count
    ]


def _c2_beaconing_features() -> list[float]:
    """Produce a 33-element feature list that indicates C2 beaconing."""
    return [
        100.0,  # 0: syscall_count
        3.0,    # 1: unique_syscalls
        0.0,    # 2: execve_count
        10.0,   # 3: openat_count
        50.0,   # 4: connect_count (many connections!)
        0.0,    # 5: ptrace_count
        0.0,    # 6: setuid_count
        5.0,    # 7: clone_count
        10.0,   # 8: write_count
        100.0,  # 9: syscall_rate
        0.0,    # 10: sensitive_file_access
        0.0,    # 11: shell_spawn
        0.0,    # 12: uid_change_attempt
        1.5,    # 13: syscall_entropy
        0.0,    # 14: priv_esc_sequence
        # Fileless (15-20)
        0.0,    # 15: memprotect_rx_count
        0.0,    # 16: anonymous_mmap_count
        0.0,    # 17: fd_based_exec_count
        0.0,    # 18: memory_region_toggle_count
        0.0,    # 19: fileless_score
        0.0,    # 20: fileless_exec
        # Ransomware (21-26)
        10.0,   # 21: unique_file_opens
        0.0,    # 22: write_to_new_files
        0.0,    # 23: delete_operations
        0.0,    # 24: file_extension_diversity
        0.0,    # 25: ransom_note_pattern
        0.0,    # 26: ransomware_score
        # Lateral movement (27-30)
        0.0,    # 27: ssh_remote_exec
        0.0,    # 28: credential_access_count
        0.0,    # 29: port_scan_count
        0.0,    # 30: lateral_movement_score
        # C2 (31-32)
        0.05,   # 31: beacon_periodicity (very regular = beacon!)
        10.0,   # 32: non_standard_port_count (malware ports!)
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestTrainAndPredict:
    """End-to-end: train on normal data, predict anomaly on malicious data."""

    def test_train_and_predict(self, tmp_path: pytest.TempPathFactory) -> None:  # type: ignore[type-arg]
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(200)]

        detector = AnomalyDetector(
            contamination=0.05,
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )
        detector.train(normal_fvs)

        # Predict on clearly anomalous vector (fileless malware).
        bad_fv = _make_fv(_fileless_malware_features())
        is_anomaly, score, reason = detector.predict(bad_fv)
        assert is_anomaly is True


class TestHeuristicRules:
    """Test heuristic rule detection for all attack categories."""

    def test_fileless_malware_heuristics(self, tmp_path: pytest.TempPathFactory) -> None:
        """T1.x: Fileless malware should trigger multiple heuristics."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        # Train first (even on minimal data)
        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Test fileless malware features
        fv = _make_fv(_fileless_malware_features())
        is_anomaly, score, reason = detector.predict(fv)

        assert is_anomaly is True
        # Should have triggered multiple fileless-related rules
        assert "fileless" in reason.lower() or "mprotect" in reason.lower()

    def test_ransomware_heuristics(self, tmp_path: pytest.TempPathFactory) -> None:
        """T2.x: Ransomware should trigger multiple heuristics."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        # Train first
        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Test ransomware features
        fv = _make_fv(_ransomware_features())
        is_anomaly, score, reason = detector.predict(fv)

        assert is_anomaly is True
        # Should have triggered ransomware rules
        assert "ransomware" in reason.lower() or "mass_file" in reason.lower() or "ransom_note" in reason.lower()

    def test_lateral_movement_heuristics(self, tmp_path: pytest.TempPathFactory) -> None:
        """T3.x: Lateral movement should trigger multiple heuristics."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        # Train first
        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Test lateral movement features
        fv = _make_fv(_lateral_movement_features())
        is_anomaly, score, reason = detector.predict(fv)

        assert is_anomaly is True
        # Should have triggered lateral movement rules
        assert "ssh" in reason.lower() or "lateral" in reason.lower() or "credential" in reason.lower()

    def test_c2_beaconing_heuristics(self, tmp_path: pytest.TempPathFactory) -> None:
        """T4.x: C2 beaconing should trigger multiple heuristics."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        # Train first
        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Test C2 beaconing features
        fv = _make_fv(_c2_beaconing_features())
        is_anomaly, score, reason = detector.predict(fv)

        assert is_anomaly is True
        # Should have triggered C2 rules
        assert "beacon" in reason.lower() or "c2" in reason.lower() or "non_standard_port" in reason.lower()


class TestOriginalHeuristics:
    """Ensure original heuristics still work correctly."""

    def test_privilege_escalation_sequence(self, tmp_path: pytest.TempPathFactory) -> None:
        """Original Rule 1: ptrace->setuid->execve sequence."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Priv esc sequence features
        fv = _make_fv([
            10.0, 3.0, 1.0, 5.0, 0.0,  # basic
            1.0, 1.0, 0.0, 5.0, 5.0, 0.0, 0.0, 1.0, 1.5, 1.0,  # priv_esc
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # fileless
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # ransomware
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # lateral
        ])
        is_anomaly, score, reason = detector.predict(fv)

        assert is_anomaly is True
        assert "priv_esc" in reason.lower()

    def test_reverse_shell_detection(self, tmp_path: pytest.TempPathFactory) -> None:
        """Original Rule 7: connect + shell_spawn = reverse shell."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Reverse shell features (connect + shell_spawn)
        fv = _make_fv([
            10.0, 3.0, 1.0, 2.0, 5.0,  # basic with connect
            0.0, 0.0, 0.0, 5.0, 5.0, 0.0, 1.0, 0.0, 1.5, 0.0,  # shell_spawn
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # fileless
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # ransomware
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # lateral
        ])
        is_anomaly, score, reason = detector.predict(fv)

        assert is_anomaly is True
        assert "reverse_shell" in reason.lower()


class TestFeatureValidation:
    """Test feature vector validation (adversarial robustness)."""

    def test_nan_detection(self, tmp_path: pytest.TempPathFactory) -> None:
        """T5.2: NaN values should cause validation failure."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Create feature vector with NaN
        features = _normal_features(rng)
        features[0] = float('nan')
        fv = _make_fv(features)

        is_valid, error = detector.validate_feature_vector(fv)
        assert is_valid is False
        assert "nan" in error.lower() or "invalid" in error.lower()

    def test_negative_values(self, tmp_path: pytest.TempPathFactory) -> None:
        """T5.3: Negative values should cause validation failure."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Create feature vector with negative value
        features = _normal_features(rng)
        features[0] = -10.0
        fv = _make_fv(features)

        is_valid, error = detector.validate_feature_vector(fv)
        assert is_valid is False
        assert "negative" in error.lower()

    def test_feature_count_mismatch(self, tmp_path: pytest.TempPathFactory) -> None:
        """Feature count mismatch should cause validation failure."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Create feature vector with wrong count
        features = [1.0] * 20  # Wrong count
        fv = _make_fv(features)

        is_valid, error = detector.validate_feature_vector(fv)
        assert is_valid is False
        assert "count" in error.lower()


class TestConfidenceScoring:
    """Test confidence scoring (adversarial robustness)."""

    def test_confidence_with_multiple_heuristics(self, tmp_path: pytest.TempPathFactory) -> None:
        """T5.7: Multiple heuristics should give higher confidence."""
        model_path = str(tmp_path / "model.pkl")
        scaler_path = str(tmp_path / "scaler.pkl")

        detector = AnomalyDetector(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=-0.5,
        )

        rng = np.random.default_rng(42)
        normal_fvs = [_make_fv(_normal_features(rng)) for _ in range(50)]
        detector.train(normal_fvs)

        # Ransomware has multiple heuristics triggered
        fv = _make_fv(_ransomware_features())
        is_anomaly, score, reason, confidence = detector.predict_with_confidence(fv)

        assert is_anomaly is True
        assert confidence >= 0.6  # Multiple rules = high confidence
