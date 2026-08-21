from datetime import datetime
from typing import Any
from uuid import UUID
from celery import shared_task
from security.database import connect_to_mongo, close_mongo_connection, get_database
from security.analysis.service import AnalysisPipelineService
from security.attack_graph.service import AttackGraphService
from security.regression.service import RegressionTestService
from security.severity.service import SeverityCalculationService
from security.baselines.service import BaselineService
from security.findings.models import Finding
import structlog

logger = structlog.get_logger()


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_analysis_pipeline(self, pipeline_id: str) -> dict[str, Any]:
    import asyncio

    async def _run():
        await connect_to_mongo()
        try:
            db = get_database()
            service = AnalysisPipelineService(db)
            pipeline = await service.run_pipeline(UUID(pipeline_id))
            return {
                "pipeline_id": str(pipeline.pipeline_id),
                "status": pipeline.overall_status.value,
                "findings_generated": len(pipeline.findings_generated),
                "completed_at": pipeline.updated_at.isoformat() if pipeline.updated_at else None,
            }
        finally:
            await close_mongo_connection()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Pipeline task failed", pipeline_id=pipeline_id, error=str(exc))
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def build_attack_graph(self, execution_id: str, target: str) -> dict[str, Any]:
    import asyncio

    async def _run():
        await connect_to_mongo()
        try:
            db = get_database()
            service = AttackGraphService(db)
            graph = await service.build_graph(UUID(execution_id), target)
            return {
                "graph_id": str(graph.graph_id),
                "nodes": len(graph.nodes),
                "edges": len(graph.edges),
                "critical_paths": len(graph.critical_paths),
            }
        finally:
            await close_mongo_connection()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Attack graph task failed", execution_id=execution_id, error=str(exc))
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def generate_regression_test(self, finding_id: str) -> dict[str, Any]:
    import asyncio

    async def _run():
        await connect_to_mongo()
        try:
            db = get_database()
            from security.findings.models import Finding
            collection = db.findings
            doc = await collection.find_one({"id": finding_id})
            if not doc:
                return {"error": "Finding not found", "finding_id": finding_id}
            finding = Finding(**doc)
            service = RegressionTestService(db)
            test = await service.generate_test(finding)
            return {
                "test_id": str(test.test_id),
                "name": test.name,
                "created_from_finding": str(test.created_from_finding) if test.created_from_finding else None,
            }
        finally:
            await close_mongo_connection()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Regression test generation failed", finding_id=finding_id, error=str(exc))
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_regression_test(self, test_id: str, execution_id: str) -> dict[str, Any]:
    import asyncio

    async def _run():
        await connect_to_mongo()
        try:
            db = get_database()
            service = RegressionTestService(db)
            run = await service.run_test(UUID(test_id), UUID(execution_id))
            return {
                "run_id": str(run.run_id),
                "result": run.result,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            }
        finally:
            await close_mongo_connection()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Regression test execution failed", test_id=test_id, error=str(exc))
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def assess_severity(self, finding_id: str, evidence_ids: list[str] | None = None) -> dict[str, Any]:
    import asyncio

    async def _run():
        await connect_to_mongo()
        try:
            db = get_database()
            from security.findings.models import Finding
            collection = db.findings
            doc = await collection.find_one({"id": finding_id})
            if not doc:
                return {"error": "Finding not found", "finding_id": finding_id}
            finding = Finding(**doc)
            service = SeverityCalculationService(db)
            evidence_uuids = [UUID(e) for e in evidence_ids] if evidence_ids else None
            assessment = await service.assess_finding(finding, evidence_uuids)
            return {
                "assessment_id": str(assessment.assessment_id),
                "severity": assessment.severity.value,
                "base_score": assessment.base_score,
                "temporal_score": assessment.temporal_score,
                "environmental_score": assessment.environmental_score,
            }
        finally:
            await close_mongo_connection()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Severity assessment failed", finding_id=finding_id, error=str(exc))
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def update_baselines(self) -> dict[str, Any]:
    import asyncio

    async def _run():
        await connect_to_mongo()
        try:
            db = get_database()
            service = BaselineService(db)
            baselines = await service.list_baselines()
            updated = 0
            for baseline in baselines:
                if baseline.execution_ids:
                    await service.create_baseline(
                        target=baseline.target,
                        name=f"{baseline.name} (auto-update {datetime.utcnow().strftime('%Y-%m-%d')})",
                        description=f"Auto-updated baseline for {baseline.target}",
                        execution_ids=baseline.execution_ids,
                        days_back=30,
                    )
                    updated += 1
            return {"baselines_updated": updated, "total_baselines": len(baselines)}
        finally:
            await close_mongo_connection()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Baseline update failed", error=str(exc))
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def check_regressions(self, threshold: float = 10.0) -> dict[str, Any]:
    import asyncio

    async def _run():
        await connect_to_mongo()
        try:
            db = get_database()
            service = BaselineService(db)
            baselines = await service.list_baselines()
            regressions = []
            for baseline in baselines:
                if baseline.execution_ids:
                    latest_execution = baseline.execution_ids[-1]
                    result = await service.detect_regression(latest_execution, threshold)
                    if result.get("regression_detected"):
                        regressions.append({
                            "baseline_id": str(baseline.baseline_id),
                            "target": baseline.target,
                            "comparison": result.get("comparison"),
                        })
            return {"regressions_detected": len(regressions), "regressions": regressions}
        finally:
            await close_mongo_connection()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Regression check failed", error=str(exc))
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def full_analysis_workflow(self, execution_id: str, target: str) -> dict[str, Any]:
    import asyncio

    async def _run():
        await connect_to_mongo()
        try:
            db = get_database()
            pipeline_service = AnalysisPipelineService(db)

            pipeline = await pipeline_service.create_pipeline(UUID(execution_id), target)
            pipeline = await pipeline_service.run_pipeline(pipeline.pipeline_id)

            graph_service = AttackGraphService(db)
            graph = await graph_service.build_graph(UUID(execution_id), target)

            severity_service = SeverityCalculationService(db)
            from security.findings.models import Finding
            findings_collection = db.findings
            cursor = findings_collection.find({"execution_id": execution_id})
            findings = [Finding(**doc) async for doc in cursor]

            for finding in findings:
                await severity_service.assess_finding(finding)

            return {
                "pipeline_id": str(pipeline.pipeline_id),
                "pipeline_status": pipeline.overall_status.value,
                "findings_count": len(findings),
                "graph_id": str(graph.graph_id),
                "graph_nodes": len(graph.nodes),
                "graph_critical_paths": len(graph.critical_paths),
            }
        finally:
            await close_mongo_connection()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Full analysis workflow failed", execution_id=execution_id, error=str(exc))
        raise self.retry(exc=exc)