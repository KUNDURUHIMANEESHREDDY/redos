import json, os
os.environ['PYTEST_CURRENT_TEST']='final_validation'
from engine.security.trust_gate import run_trust_gate
trust = run_trust_gate()
with open('trust_output.json', 'w') as f:
    json.dump(trust, f, indent=2, default=str)
print('Done. overall_status:', trust['overall_status'])
print('overall_score:', trust['overall_score'])
print('blocking_failures:', trust['blocking_failures'])