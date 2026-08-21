# RedOS Operations Module

## Operations Dashboard

```python
from redos.operations import OperationsDashboard
import asyncio
import json

async def main():
    dashboard = OperationsDashboard(org_id="org_456")
    
    # Get operational dashboards
    dashboards = await dashboard.get_all_dashboards()
    
    # Campaign throughput dashboard
    throughput = dashboards.get('campaign_throughput')
    print(f"Campaign Throughput:")
    print(f"  Total campaigns: {throughget['total']}")
    print(f"  Completed: {throughput['completed']}")
    print(f"  Failed: {throughput['failed']}")
    print(f"  Cancelled: {throughput['cancelled']}")
    print(f"  Average duration: {throughput['avg_duration_minutes']} minutes")
    
    # Attack success dashboard
    success = dashboards.get('attack_success')
    print(f"\nAttack Success:")
    print(f"  Total attacks: {success['total_attack']}")
    print(f"  Successful: {success['successful']}")
    print(f"  Blocked: {success['blocked']}")
    print(f"  Success rate: {success['success_rate']:.1f}%")
    
    # Worker health dashboard
    health = dashboards.get('worker_health')
    print(f"\nWorker Health:")
    print(f"  Total workers: {health['total_workers']}")
    print(f"  Active: {health['active_workers']}")
    print(f"  Idle: {health['idle_workers']}")
    print(f"  Utilization: {health['utilization_ratio']:.1f}%")
    print(f"  Unhealthy: {health['unhealthy_workers']}")
    
    # Queue latency dashboard
    latency = dashboards.get('queue_latency')
    print(f"\nQueue Latency:")
    print(f"  Average latency: {latency['avg_latency_seconds']} seconds")
    print(f"  P95 latency: {latency['p95_latency_seconds']} seconds")
    print(f"  Max latency: {latency['max_latency_seconds']} seconds")
    print(f"  Over threshold: {latency['over_threshold_count']} events")
    
    # Target failures dashboard
    failures = dashboards.get('target_failures')
    print(f"\nTarget Failures:")
    print(f"  Total targets: {failures['total_targets']}")
    print(f"  Failed targets: {failures['failed_targets']}")
    print(f"  Failure rate: {failures['failure_rate']:.1f}%")
    print(f"  Most failed target: {failures['most_failed_target']}")
    
    # Regression rate dashboard
    regression = dashboards.get('regression_rate')
    print(f"\nRegression Rate:")
    print(f"  Total regressions: {regression['total_regressions']}")
    print(f"  Detected: {regression['detected']}")
    print(f"  False positives: {regression['false_positives']}")
    print(f"  Regression rate: {regression['regression_rate']:.1f}%")
    
    # Critical findings dashboard
    critical = dashboards.get('critical_findings')
    print(f"\nCritical Findings:")
    print(f"  Active critical: {critical['active_critical']}")
    print(f"  Older than 24h: {critical['older_than_24h']}")
    print(f"  Older than 7d: {critical['older_than_7d']}")
    print(f"  Mean time to remediate: {critical['mttr_hours']} hours")
    
    # Risk trend dashboard
    trend = dashboards.get('risk_trend')
    print(f"\nRisk Trend:")
    print(f"  Current posture: {trend['current_posture']:.1f}/10")
    print(f"  Trend direction: {trend['trend_direction']}")
    print(f"  30-day change: {trend['thirty_day_change']:.1f} points")
    print(f"  Projected: {trend['projected_posture']:.1f}/10")
    
    # Cost/token usage dashboard
    cost = dashboards.get('cost_token_usage')
    print(f"\nCost/Token Usage:")
    print(f"  Daily cost: ${cost['daily_cost_usd']:.2f}")
    print(f"  Monthly forecast: ${cost['monthly_forecast_usd']:.2f}")
    print(f"  Tokens used today: {cost['tokens_used_today_million']}M")
    print(f"  Token budget: {cost['token_budget_million']}M")
    print(f"  Budget utilization: {cost['utilization_percent']:.1f}%")
    
    # Summary
    print(f"\n=== Operations Summary ===")
    print(f"Posture: {trend['current_posture']:.1f}/10 ({trend['trend_direction']})")
    print(f"Success rate: {success['success_rate']:.1f}%")
    print(f"Utilization: {health['utilization_ratio']:.1f}%")
    print(f"Cost today: ${cost['daily_cost_usd']:.2f}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Operations Dashboard API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/operations/dashboard` | Get all operational dashboards |
| `GET` | `/api/v1/operations/dashboard/campaign-throughput` | Campaign throughput metrics |
| `GET` | `/api/v1/operations/dashboard/attack-success` | Attack success metrics |
| `GET` | `/api/v1/operations/dashboard/worker-health` | Worker health metrics |
| `GET` | `/api/v1/operations/dashboard/queue-latency` | Queue latency metrics |
| `GET` | `/api/v1/operations/dashboard/target-failures` | Target failure metrics |
| `GET` | `/api/v1/operations/dashboard/regression-rate` | Regression rate metrics |
| `GET` | `/api/v1/operations/dashboard/critical-findings` | Critical findings metrics |
| `GET` | `/api/v1/operations/dashboard/risk-trend` | Risk trend metrics |
| `GET` | `/api/v1/operations/dashboard/cost-token-usage` | Cost and token usage |

## Operations Health Check

```python
from redos.operations import operations_health_check

# Run comprehensive health check
health = await operations_health_check(org_id="org_456")

print(f"Overall status: {health['overall_status']}")
print(f"Checks passed: {health['checks_passed']}/{health['total_checks']}")
print(f"Warnings: {health['warnings']}")
print(f"Critical issues: {health['critical_issues']}")

for check in health['checks']:
    print(f"  {check['name']}: {check['status']}")
    if check['details']:
        print(f"    {check['details']}")
```

## Operations Health Check Components

| Component | Check | Threshold | Alert |
|-----------|-------|-----------|-------|
| Campaign throughput | Completion rate > 95% | < 95% | warning |
| Attack success | Success rate > 90% | < 90% | critical |
| Worker health | Utilization 30-85% | < 30% or > 85% | warning |
| Queue latency | P95 < 300 seconds | > 300 seconds | critical |
| Target failures | Rate < 10% | > 10% | warning |
| Regression rate | Rate < 5% | > 5% | critical |
| Critical findings | Age < 7 days > 0 | Some | warning |
| Risk trend | Posture > 7/10 | < 7/10 | warning |
| Cost/token | Utilization < 90% | > 90% | critical |

## Example: Complete Operations Monitoring

```python
import asyncio
from redos.operations import OperationsDashboard, operations_health_check

async def operations_monitoring():
    org_id = "org_456"
    
    # Get all dashboards
    dashboard = OperationsDashboard(org_id=org_id)
    dashboards = await dashboard.get_all_dashboards()
    
    # Run health check
    health = await operations_health_check(org_id=org_id)
    
    # Print summary
    print("=" * 60)
    print("REDOS OPERATIONS DASHBOARD")
    print("=" * 60)
    
    # Print each dashboard section
    for section_name, data in dashboards.items():
        print(f"\n{section_name.replace('_', ' ').title()}:")
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, float):
                    print(f"  {key}: {value:.2f}")
                else:
                    print(f"  {key}: {value}")
    
    # Print health check results
    print(f"\nHealth Check:")
    print(f"  Status: {health['overall_status']}")
    print(f"  Checks: {health['checks_passed']}/{health['total_checks']}")
    
    # Print alerts
    if health['critical_issues']:
        print(f"\n  CRITICAL: {len(health['critical_issues'])} issues require attention")
    if health['warnings']:
        print(f"  WARN: {len(health['warnings'])} issues need attention")
    
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(operations_monitoring())
```