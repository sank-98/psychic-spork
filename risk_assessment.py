class RiskAssessment:
    def __init__(self):
        self.risks = {
            "unauthorized_access": {"severity": 8, "likelihood": 7},  # 1-10 scale
            "ddos_attack": {"severity": 9, "likelihood": 5},
            "malware": {"severity": 10, "likelihood": 6}
        }
    
    def assess_risk(self, risk_type):
        """
        Assesses the severity and likelihood of a risk. Returns a risk score based
        on both factors.
        """
        if risk_type not in self.risks:
            return "Unknown risk type"
        
        risk = self.risks[risk_type]
        score = (risk['severity'] + risk['likelihood']) / 2
        return f"Risk Type: {risk_type}, Severity: {risk['severity']}, Likelihood: {risk['likelihood']}, Score: {score}"

    def assess_all_risks(self):
        """
        Assess all risks identified and return a summary of each.
        """
        results = {}
        for risk_type in self.risks:
            results[risk_type] = self.assess_risk(risk_type)
        return results

# Example of running the assessment
if __name__ == "__main__":
    risk_assessment = RiskAssessment()
    print(risk_assessment.assess_all_risks())
