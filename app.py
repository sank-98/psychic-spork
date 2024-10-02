from flask import Flask, render_template
from risk_identification import RiskIdentification
from risk_assessment import RiskAssessment
from risk_mitigation import RiskMitigation

app = Flask(__name__)

# Initialize components
risk_id = RiskIdentification("server_logs.txt")
risk_assess = RiskAssessment()
risk_mitigate = RiskMitigation()

@app.route('/')
def home():
    unauthorized_access = risk_id.detect_unauthorized_access()
    ddos_risk = risk_id.detect_ddos_attack()
    malware_activity = risk_id.detect_malware_activity()

    risks = risk_assess.assess_all_risks()
    mitigations = risk_mitigate.suggest_all_mitigations()

    return render_template('dashboard.html', unauthorized_access=unauthorized_access, ddos_risk=ddos_risk, 
                           malware_activity=malware_activity, risks=risks, mitigations=mitigations)

if __name__ == '__main__':
    app.run(debug=True)
