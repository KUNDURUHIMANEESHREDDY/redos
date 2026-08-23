@echo off
cd C:\Users\himaneeshreddyk\Downloads\redos
set PYTEST_CURRENT_TEST=final_validation
python -c "import json, os; os.environ['PYTEST_CURRENT_TEST']='final_validation'; from engine.security.trust_gate import run_trust_gate; trust = run_trust_gate(); print('overall_status:', trust['overall_status']); print('overall_score:', trust['overall_score']); print('blocking_failures:', trust['blocking_failures']); [print('  ', g['Gate'], ': actual=', g['Actual'], ' status=', g['Status']) for g in trust['gates']]"