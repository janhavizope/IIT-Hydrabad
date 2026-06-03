from app.models.analysis_context import AnalysisContext


class RiskEngine:
    """Service class for malware risk scoring."""

    def calculate_risk(self, context: AnalysisContext):
        """Calculate a simple rule-based malware risk score."""
        permissions = getattr(context, "permissions", []) or []

        permission_scores = {
            "READ_SMS": 25,
            "SEND_SMS": 25,
            "RECEIVE_SMS": 20,
            "WRITE_EXTERNAL_STORAGE": 15,
            "READ_CONTACTS": 15,
            "ACCESS_FINE_LOCATION": 10,
            "RECORD_AUDIO": 20,
            "INTERNET": 10,
            "ACCESS_NETWORK_STATE": 5,
        }

        risk_score = 0
        flags = []

        for permission in permissions:
            permission_name = permission.split(".")[-1]
            if permission_name in permission_scores:
                risk_score += permission_scores[permission_name]
                flags.append(permission_name)

        if not flags:
            return {
                "risk_score": 0,
                "risk_level": "LOW",
                "flags": [],
                "explanation": "No risky permissions detected",
            }

        if risk_score <= 30:
            risk_level = "LOW"
        elif risk_score <= 60:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        readable_flags = [flag.lower().replace("_", " ") for flag in flags]

        if risk_level == "HIGH":
            explanation = (
                "This app requests sensitive permissions such as "
                + ", ".join(readable_flags)
                + ", which are commonly associated with malware behavior."
            )
        elif risk_level == "MEDIUM":
            explanation = (
                "This app requests several sensitive permissions such as "
                + ", ".join(readable_flags)
                + ", so it should be reviewed with moderate caution."
            )
        else:
            explanation = "This app requests only low-risk permissions and appears relatively safe."

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "flags": flags,
            "explanation": explanation,
        }
