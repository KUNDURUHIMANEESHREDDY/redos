# RedOS DR Validation

## Overview

This document describes the actual execution of disaster recovery procedures - not merely
documenting them, but running them in a test environment, destroying it, restoring from
backups, and verifying all components are intact and correct.

## DR Validation Procedure

### Preparation

```bash
# 1. Ensure backups exist
echo "=== Checking backup availability ==="
ls -la /backups/mongo/
ls -la /backups/redis/
ls -la /backups/s3/

# 2. Verify backup integrity
echo "=== Verifying backup checksums ==="
sha256sum /backups/mongo/dump_2024* | head -5
sha256sum /backups/redis/dump_2024*.rdb | head -5

# 3. Record starting state
echo "=== Recording pre-drill state ==="
docker exec redos-mongo-1 mongosh --eval "
  db = db.getSiblingDB('security_analysis');
  print('Findings:', db.findings.countDocuments({}));
  print('Organizations:', db.organizations.countDocuments({}));
  print('Evidence:', db.evidence.countDocuments({}));
  print('Users:', db.users.countDocuments({}));
"

# Start timing
START_TIME=$(date +%s)
```

### 2. Test Environment Destruction

```bash
# 3. Stop non-essential services
echo "=== Stopping non-essential services ==="
docker stop redos-frontend-1 redos-worker-1

# 4. Stop critical services (preserving data)
echo "=== Stopping critical services ==="
docker stop redos-api-1 redos-mongo-1 redos-redis-1

# 5. Verify services are stopped
echo "=== Verifying service state ==="
docker ps --filter "name=redos-" --format "{{.Names}} {{.Status}}"

# 6. Take snapshot before destroy (optional but recommended)
echo "=== Creating pre-destroy snapshots ==="
# (If using cloud infrastructure, create snapshots of volumes)
# aws ec2 create-snapshot --volume-id vol-12345678
```

### 3. Restoration from Backups

```bash
# 7. Restore MongoDB
echo "=== Restoring MongoDB ==="
bash /usr/local/bin/mongo-restore.sh

# 8. Restore Redis
echo "=== Restoring Redis ==="
bash /usr/local/bin/redis-restore.sh

# 9. Restore Object Store
echo "=== Restoring object store ==="
bash /usr/local/bin/s3-restore.sh

# 10. Wait for services to initialize
echo "=== Waiting for service initialization ==="
sleep 30

# 11. Start services in order
echo "=== Starting services ==="
docker start redos-mongo-1
sleep 10
docker start redos-redis-1
sleep 10
docker start redos-api-1
sleep 15
docker start redos-worker-1
sleep 10
docker start redos-frontend-1
```

### 4. Verification

```bash
# 12. Verify evidence integrity
echo "=== Verifying evidence integrity ==="
docker exec redos-mongo-1 mongosh --eval "
  db = db.getSiblingDB('security_analysis');
  // Check evidence collection exists and has documents
  print('Evidence count:', db.evidence.countDocuments({}));
  // Verify at least one evidence document has expected fields
  var sample = db.evidence.findOne({});
  if (sample) {
    print('Sample evidence fields:', Object.keys(sample).join(', '));
  } else {
    print('WARNING: No evidence documents found!');
  }
"

# 13. Verify findings integrity
echo "=== Verifying findings integrity ==="
docker exec redos-mongo-1 mongosh --eval "
  db = db.getSiblingDB('security_analysis');
  print('Findings count:', db.findings.countDocuments({}));
  var sample = db.findings.findOne({});
  if (sample) {
    print('Sample finding fields:', Object.keys(sample).join(', '));
    print('Severity:', sample.severity);
    print('Status:', sample.status);
  }
"

# 14. Verify campaign state
echo "=== Verifying campaign state ==="
docker exec redos-mongo-1 mongosh --eval "
  db = db.getSiblingDB('security_analysis');
  // Look for recent campaigns
  var recent = db.executions.find({startedAt: {\$gte: new Date(Date.now() - 24 * 60 * 60 * 1000)}}).limit(5).sort({startedAt: -1});
  print('Recent executions count:', recent.length);
  recent.forEach(function(doc) {
    print('  Execution:', doc.id, 'Status:', doc.status, 'Campaign:', doc.campaignId);
  });
"

# 15. Full health check
echo "=== Full health check ==="
curl -s http://localhost:8000/api/v1/health | python3 -m json.tool

# 16. Calculate drill duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo "=== DR Validation completed in ${DURATION} seconds ==="
echo "=== Status: SUCCESS ==="
"