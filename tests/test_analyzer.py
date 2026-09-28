import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.analyzer import analyze_file

def test_sample_detects_multiple_indicators():
    result = analyze_file(Path(__file__).parents[1] / "samples" / "sample_phishing.eml")
    assert result["score"] >= 50
    assert result["severity"] in {"HIGH", "CRITICAL"}
    assert result["urls"]
    assert any("Reply-To" in f["title"] for f in result["findings"])
