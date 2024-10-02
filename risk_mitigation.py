class RiskMitigation:
    def __init__(self):
        self.mitigation_strategies = {
            "unauthorized_access": "Ensure strong authentication and role-based access control (RBAC)",
            "ddos_attack": "Use rate limiting and IP blocking to mitigate potential DDoS attacks",
            "malware": "Ensure antivirus software is up-to-date and systems are patched"
        }
    
    def suggest_mitigation(self, risk_type):
        """
        Suggests a mitigation strategy for a given risk type.
        """
        return self.mitigation_strategies.get(risk_type, "No mitigation strategy found for this risk")

    def suggest_all_mitigations(self):
        """
        Returns mitigation strategies for all known risks.
        """
        strategies = {}
        for risk_type in self.mitigation_strategies:
            strategies[risk_type] = self.suggest_mitigation(risk_type)
        return strategies

# Example usage
if __name__ == "__main__":
    risk_mitigation = RiskMitigation()
    print(risk_mitigation.suggest_all_mitigations())
