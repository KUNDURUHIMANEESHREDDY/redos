# RedOS Disaster Recovery

## Overview

Disaster recovery procedures ensure RedOS can recover from catastrophic failures, data loss,
or complete infrastructure outages. This document covers backup strategies, restore procedures,
disaster recovery drills, and business continuity planning.

## Backup Strategies

### Backup Types

| Backup Type | Contents | Frequency | Retention | RPO | RTO |
|-------------|----------|-----------|-----------|-----|-----|
| **MongoDB Snapshots** | Database collections, validators, indexes | Daily (2 AM) | 30 days | 1 hour | 4 hours |
| **Redis RDB** | Cache, session data, rate limits | Hourly (BGSAVE) | 7 days | 15 minutes | 30 minutes |
| **Object Store** | Evidence files, archives, backups | Every 6 hours | 90 days | 1 hour | 2 hours |
| **Configuration** | Docker compose, env files, k8s manifests | On change (git commit) | Indefinite | N/A | N/A |
| **Database Migrations** | Alembic scripts, schema changes | On change (git commit) | Indefinite | N/A | N/A |

### MongoDB Backup

```bash
#!/bin/bash
# mongo-backup.sh
set -e

BACKUP_DIR="/backups/mongo"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Run mongodump
mongodump \
  --uri="mongodb://localhost:27017/security_analysis" \
  --out="${BACKUP_DIR}/dump_${DATE}"

# Verify backup integrity
if [ -d "${BACKUP_DIR}/dump_${DATE}" ]; then
  echo "✅ MongoDB backup completed: ${DATE}"
else
  echo "❌ MongoDB backup failed"
  exit 1
fi

# Clean old backups
find "${BACKUP_DIR}" -name "dump_*" -type d -mtime +${RETENTION_DAYS} -delete

# Report
BACKUP_COUNT=$(find "${BACKUP_DIR}" -name "dump_*" -type d | wc -l)
echo "Backup count: ${BACKUP_COUNT}"
```

### Redis Backup

```bash
#!/bin/bash
# redis-backup.sh
set -e

BACKUP_DIR="/backups/redis"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
RETENTION_DAYS=7

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Create Redis RDB snapshot
docker exec redis redis-cli BGSAVE

# Wait for snapshot and copy
sleep 2

# Copy RDB file from Redis container
docker cp redis:/dump/dump.rdb "${BACKUP_DIR}/dump_${DATE}.rdb"

# Verify snapshot was created
STATUS=$(docker exec redis redis-cli INFO persistence | grep rdb_last_save_time)
echo "Redis snapshot: ${STATUS}"

# Clean old backups
find "${BACKUP_DIR}" -name "dump_*.rdb" -mtime +${RETENTION_DAYS} -delete

echo "✅ Redis backup completed: ${DATE}"
```

### Object Store Backup (S3/Minio)

```bash
#!/bin/bash
# s3-backup.sh
set -e

BACKUP_DIR="/backups/s3"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
RETENTION_DAYS=90

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Using AWS CLI
aws s3 sync /data/backups/s3 "s3://redos-backups/${DATE}/" \
  --storage-class STANDARD_IA \
  --expire-in ${RETENTION_DAYS}d

# Using MinIO client
mc alias set myminio http://localhost:9000 minioaccesskey miniosecretkey
mc mirror /data/backups/s3 myminio/redos-backups/${DATE} \
  --archive-glacier-id myminio \
  --longevity-marker-days ${RETENTION_DAYS}d

echo "✅ Object store backup completed: ${DATE}"
```

## Restore Procedures

### MongoDB Restore

```bash
#!/bin/bash
# mongo-restore.sh
set -e

RESTORE_DIR="/backups/mongo/dump_2024-01-15"
DATE=$(date +%Y-%m-%d)

# Stop application (optional, recommended)
docker stop redos-api-1

# Restore MongoDB
docker exec -i redos-mongo-1 mongorestore "/backups/mongo/dump_2024-01-15/"

# Verify restore
docker exec redos-mongo-1 mongosh --eval "
  db = db.getSiblingDB('security_analysis');
  print('Users:', db.users.countDocuments({}));
  print('Organizations:', db.organizations.countDocuments({}));
  print('Findings:', db.findings.countDocuments({}));
  print('Evidence:', db.evidence.countDocuments({}));
"

# Restart application
docker start redos-api-1

echo "✅ MongoDB restore completed: ${DATE}"
```

### Redis Restore

```bash
#!/bin/bash
# redis-restore.sh
set -e

RESTORE_RDB="/backups/redis/dump_2024-01-15.rdb"
DATE=$(date +%Y-%m-%d)

# Stop Redis temporarily
docker stop redos-redis-1

# Replace data file
docker cp "/backups/redis/dump_2024-01-15.rdb" redos-redis-1:/dump/dump.rdb

# Restart Redis
docker start redos-redis-1

# Verify data integrity
docker exec redos-redis-1 redis-cli DBSIZE

echo "✅ Redis restore completed: ${DATE}"
```

### Object Store Restore

```bash
#!/bin/bash
# s3-restore.sh
set -e

DATE=$(date +%Y-%m-%d)
RESTORE_BUCKET="s3://redos-backups/${DATE}"

# Using AWS CLI
aws s3 cp "s3://redos-backups/${DATE}/" /data/backups/s3/ \
  --recursive

# Using MinIO client
mc mirror myminio/redos-backups/${DATE} /data/backups/s3/ \
  --overwrite

echo "✅ Object store restore completed: ${DATE}"
```

## Disaster Recovery Drills

### DR Drill Schedule

| Drill Type | Frequency | Scope | Duration | Success Criteria |
|-----------|-----------|-------|----------|-----------------|
| **Backup Verification** | Weekly | Verify backups are valid and complete | 30 minutes | All backup files restore successfully |
| **MongoDB Restore** | Monthly | Full MongoDB restore from backup | 2 hours | Database is fully restored and functional |
| **Redis Restore** | Monthly | Full Redis restore from backup | 1 hour | Redis is fully functional |
| **Full DR Drill** | Quarterly | End-to-end outage simulation | 4 hours | All services restore within RTO |
| **Compliance DR** | Quarterly | Compliance-specific data restore | 2 hours | All compliance data restored intact |
| ** disaster Recovery Full** | Annually | Complete infrastructure failure | 8 hours | All services operational within SLA |

### DR Drill Procedure

```bash
#!/bin/bash
# dr-drill.sh - Quarterly disaster recovery drill
set -e

echo "=== RedOS Disaster Recovery Drill ==="
echo "Start time: $(date)"
echo ""

# 1. Announce drill
echo "1. Announcing drill to stakeholders..."
# (send notifications to ops team, leadership)

# 2. Stop non-critical services
echo "2. Stopping non-critical services..."
docker stop redos-api-1 redos-worker-1 redos-frontend-1

# 3. Simulate outage
echo "2. Simulating complete infrastructure outage..."
docker stop redos-mongo-1 redos-redis-1

# 4. Execute restore
echo "3. Executing MongoDB restore..."
bash /usr/local/bin/mongo-restore.sh

echo "4. Executing Redis restore..."
bash /usr/local/bin/redis-restore.sh

echo "5. Executing object store restore..."
bash /usr/local/bin/s3-restore.sh

# 5. Start services
echo "6. Starting services..."
docker start redos-mongo-1 redos-redis-1
sleep 10  # Wait for services to initialize
docker start redos-api-1 redos-worker-1 redos-frontend-1

# 6. Verify all services
echo "7. Verifying service health..."
sleep 15
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/v1/health)
echo "API health code: ${HEALTH}"

echo "8. Verifying data integrity..."
docker exec redos-mongo-1 mongosh --eval "
  db = db.getSiblingDB('security_analysis');
  print('Findings:', db.findings.countDocuments({}));
  print('Organizations:', db.organizations.countDocuments({}));
"

# 9. Report results
echo "9. DR drill completed"
echo "End time: $(date)"
echo "Duration: $(($(date +%s) - START_TIME)) seconds"
echo ""

# 10. Send report
# (send DR drill report to leadership, store in compliance records)
```

### RPO and RTO Definitions

| Metric | Definition | Target | Maximum Acceptable |
|--------|------------|--------|--------------------|
| **RPO** (Recovery Point Objective) | Maximum acceptable data loss | 1 hour | 24 hours |
| **RTO** (Recovery Time Objective) | Maximum acceptable downtime | 4 hours | 24 hours |
| **BPO** (Backup Point Objective) | Frequency of backups | Every 15-30 mins (Redis) / Daily (Mongo) | Real-time / Weekly |

## Health Checks

### API Health Endpoint

```
GET /api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "database": "connected",
  "redis": "connected",
  "object_store": "connected",
  "timestamp": "2024-01-15T10:30:00Z",
  "details": {
    "mongo": {
      "status": "up",
      "document_count": 1247,
      "latest_backup": "2024-01-15T02:00:00Z"
    },
    "redis": {
      "status": "up",
      "used_memory": "45MB",
      "latest_backup": "2024-01-15T01:30:00Z"
    },
    "object_store": {
      "status": "up",
      "latest_backup": "2024-01-15T01:00:00Z",
      "backup_age_hours": 9
    }
  }
```

### Kubernetes Health Checks

```yaml
# In deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redos-api
spec:
  template:
    spec:
      containers:
        - name: api
          healthcheck:
            test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
            initialDelaySeconds: 30
            period: 30s
            timeout: 5s
            retries: 3
```

### Component Health

| Component | Check | Frequency | Alert If |
|-----------|-------|-----------|----------|
| **API** | `/api/v1/health` | Every 30s | 3 consecutive failures |
| **MongoDB** | `mongosh --eval "db.adminCommand('ping')"` | Every 30s | Ping fails |
| **Redis** | `redis-cli PING` | Every 30s | Pong not received |
| **Object Store** | `mc ping` or `aws s3 head bucket` | Every 1 minute | Response fails |
| **Workers** | Celery `ping` | Every 15s | No response |
| **Disk Usage** | `df -h /` | Every 5 min | > 90% used |
| **Memory Usage** | `free -m` | Every 5 min | > 90% used |
| **CPU Usage** | `top -bn1 | grep %CPU` | Every 5 min | > 80% average |

## Alerting

### Alert Channels

| Channel | Purpose | severity Levels |
|---------|---------|-----------------|
| **Slack** #redos-alerts | Team notifications | critical, warning, info |
| **Email** ops-team@example.com | Leadership notifications | critical only |
| **PagerDuty** | On-call escalation | critical, high |
| **Opsgenie** | Incident management | critical, high, warning |
| **Custom Webhook** | External systems | all levels |

### Alert Examples

```yaml
# Alert: MongoDB connection lost
- name: "MongoDB connection lost"
  query: |
    sum(rate(mongo_db_connection_pool_checks_failed_total[1m])) > 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "MongoDB connection pool check failures"
    description: "MongoDB connection checks have been failing for over 1 minute"
    runbook: "mongodb_lost_connection"

- name: "Redis memory usage high"
  query: |
    redis_memory_used_bytes > 0.9 * redis_memory_limit_bytes
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Redis memory usage exceed 90%"
    description: "Redis is using more than 90% of allocated memory"
    runbook: "redis_memory_high"

- name: "API health check failed"
  query: |
    http_requests{status=~"5.."}{handler="/api/v1/health"} > 0
  for: 3m
  labels:
    severity: critical
  annotations:
    summary: "API health endpoint returning errors"
    description: "API /api/v1/health is returning 5xx errors"
    runbook: "api_health_check_failed"

- name" "Backup job failed"
  query: |
    mongodb_backup_status != "success" or redis_backup_status != "success"
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "Daily backup job has not completed successfully"
    description: "Either MongoDB or Redis backup has failed for over 1 hour"
    runbook: "backup_job_failed"
```

## Business Continuity

### Failover Configuration

```yaml
# Failover setup in Kubernetes
apiVersion: v1
kind: Service
metadata:
  name: redos-api
spec:
  type: LoadBalancer
  selector:
    app: redos-api
  ports:
    - port: 80
      targetPort: 8000
  # Session affinity for sticky sessions
  sessionAffinity: "ClientIP"
  
  # External DNS failover
  externalIPs:
    - "10.0.0.1"  # Primary
    - "10.0.0.2"  # Secondary failover
```

### Load Balancer Configuration

```yaml
# HAProxy configuration
frontend http_front
    bind *:80
    default_backend http_back

backend http_back
    balance roundrobin
    option httpchk GET /api/v1/health
    server redos-api-1 10.0.0.1:8000 check inter 5s rise 3 fall 3
    server redos-api-2 10.0.0.2:8000 check inter 5s rise 3 fall 3
```

### Readiness/Liveness Probes

```yaml
# Kubernetes probe configuration
apiVersion: v1
kind: Pod
metadata:
  name: redos-api
spec:
  containers:
    - name: api
      livenessProbe:
        httpGet:
          path: /api/v1/health
          port: 8000
        initialDelaySeconds: 60
        period: 40s
        failureThreshold: 5
      
      readinessProbe:
        httpGet:
          path: /api/v1/health
          port: 8000
        initialDelaySeconds: 10
        period: 10s
        failureThreshold: 3
```

## Compliance & Audit

### Backup Audit Log

```json
{
  "backup_id": "backup_20240115_0200",
  "type": "mongodb",
  "organization_id": "org_123",
  "started_at": "2024-01-15T02:00:00Z",
  "completed_at": "2024-01-15T02:05:00Z",
  "status": "success",
  "documents_backed_up": 1247,
  "size_gb": 2.3,
  "checksum": "sha256:abc123...",
  "stored_at": "s3://redos-backups/2024-01-15/",
  " backed_up_by": "mongo-backup.sh v2.1.0",
  "verified_at": "2024-01-15T02:06:00Z",
  "dr_drill_count": 3
}
```

### Restore Audit Log

```json
{
  "restore_id": "restore_20240116_0400",
  "type": "full_database",
  "organization_id": "org_123",
  "started_at": "2024-01-16T04:00:00Z",
  "completed_at": "2024-01-16T04:15:00Z",
  "status": "success",
  "source_backup": "backup_20240115_0200",
  "documents_restored": 1247,
  "execution_time_minutes": 15,
  "data_integrity_verified": true,
  "verified_by": "ops-team",
  "dr_drill_id": "drill_quarterly_0124"
}
```

## Documentation & Runbooks

### Required Runbooks

1. **mongo-backup.sh** - MongoDB backup procedure
2. **mongo-restore.sh** - MongoDB restore procedure
3. **redis-backup.sh** - Redis backup procedure
4. **redis-restore.sh** - Redis restore procedure
5. **s3-backup.sh** - Object store backup procedure
6. **s3-restore.sh** - Object store restore procedure
7. **dr-drill.sh** - Quarterly disaster recovery drill
8. **api-health-check.sh** - API health check script
9. **component-health.sh** - Component health monitor script
10. **dr-report.sh** - DR drill report generator

### Runbook Location

```
├── docs/
│   ├── INTEGRATIONS.md
│   ├── SECURITY_GATES.md
│   ├── ENTERPRISE.md
│   └── DISASTER_RECOVERY.md
├── scripts/
│   ├── mongo-backup.sh
│   ├── mongo-restore.sh
│   ├── redis-backup.sh
│   ├── redis-restore.sh
│   ├── s3-backup.sh
│   ├── s3-restore.sh
│   └── dr-drill.sh
└── ops/
    ├── runbooks/
    │   ├── mongo.md
    │   ├── redis.md
    │   ├── s3.md
    │   └── dr.md
    └── checklists/
        ├── daily.md
        ├── weekly.md
        ├── monthly.md
        └── quarterly.md
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-08-20 | Initial disaster recovery documentation |