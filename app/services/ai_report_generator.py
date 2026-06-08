class AIReportGenerator:
    def __init__(self, raw_report):
        self.raw_report = raw_report

    def generate(self):
        # Simple fallback AI summary (safe version)
        if not self.raw_report:
            return {
                "summary": "No data available",
                "risk": "UNKNOWN"
            }

        # basic intelligent summarization logic
        risk_score = self.raw_report.get("risk_score", 0)
        label = self.raw_report.get("label", "UNKNOWN")

        return {
            "summary": f"APK analysis completed with risk score {risk_score}%",
            "risk_level": label,
            "recommendation": (
                "Install only if source is trusted"
                if risk_score < 50
                else "Do NOT install - high risk detected"
            )
        }