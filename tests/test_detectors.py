from __future__ import annotations

from agentbom.detectors import DetectionContext, DetectionResult, detect_in_file


class CustomDetector:
    name = "custom"

    def detect(self, context: DetectionContext) -> DetectionResult:
        return DetectionResult(
            {
                "providers": [
                    {"name": "custom", "path": context.relpath, "confidence": "low"}
                ]
            }
        )


def test_detect_in_file_accepts_custom_detectors():
    result = detect_in_file("agent.py", "ignored", (CustomDetector(),))

    assert result.findings == {
        "providers": [{"name": "custom", "path": "agent.py", "confidence": "low"}]
    }


def test_policy_detector_marks_policy_files_without_text():
    result = detect_in_file("SECURITY.md", None)

    assert result.has_policy is True
