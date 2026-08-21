from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
from security.analytics.models import (
    AnalyticsQuery,
    AnalyticsResult,
    DashboardWidget,
    AnalyticsReport,
    AnalyticsType,
    TimeGranularity,
)
from security.findings.models import Finding
from security.evidence.models import Evidence
from security.posture.models import PostureSnapshot
import structlog

logger = structlog.get_logger()


class AnalyticsEngine:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.queries_collection = self.db.analytics_queries
        self.results_collection = self.db.analytics_results
        self.widgets_collection = self.db.dashboard_widgets
        self.reports_collection = self.db.analytics_reports

    async def execute_query(self, query: AnalyticsQuery) -> AnalyticsResult:
        start_time = datetime.utcnow()

        if query.analytics_type == AnalyticsType.ATTACK_COVERAGE:
            data = await self._query_attack_coverage(query)
        elif query.analytics_type == AnalyticsType.RISK_TREND:
            data = await self._query_risk_trend(query)
        elif query.analytics_type == AnalyticsType.FINDING_DISTRIBUTION:
            data = await self._query_finding_distribution(query)
        elif query.analytics_type == AnalyticsType.REMEDIATION_EFFECTIVENESS:
            data = await self._query_remediation_effectiveness(query)
        elif query.analytics_type == AnalyticsType.REGRESSION_ANALYSIS:
            data = await self._query_regression_analysis(query)
        elif query.analytics_type == AnalyticsType.EVIDENCE_QUALITY:
            data = await self._query_evidence_quality(query)
        elif query.analytics_type == AnalyticsType.TARGET_COMPARISON:
            data = await self._query_target_comparison(query)
        elif query.analytics_type == AnalyticsType.MODEL_PERFORMANCE:
            data = await self._query_model_performance(query)
        else:
            data = {"data_points": [], "aggregations": {}}

        result = AnalyticsResult(
            query_id=query.query_id,
            analytics_type=query.analytics_type,
            target_id=query.target_ids[0] if query.target_ids else UUID("00000000-0000-0000-0000-000000000000"),
            data_points=data["data_points"],
            aggregations=data["aggregations"],
            metadata={
                "query_time_ms": int((datetime.utcnow() - start_time).total_seconds() * 1000),
                "filters_applied": query.filters,
            },
        )
        await self.results_collection.insert_one(result.model_dump())
        return result

    async def _query_attack_coverage(self, query: AnalyticsQuery) -> dict[str, Any]:
        target_ids = query.target_ids or await self._get_all_target_ids()
        points = []

        for target_id in target_ids:
            latest = await self.db.attack_coverage_analytics.find_one(
                {"target_id": str(target_id)},
                sort=[("computed_at", -1)]
            )
            if latest:
                points.append({
                    "target_id": str(target_id),
                    "timestamp": latest["computed_at"],
                    "coverage_percentage": latest["coverage_percentage"],
                    "covered_vectors": latest["covered_vectors"],
                    "total_vectors": latest["total_attack_vectors"],
                })

        return {
            "data_points": points,
            "aggregations": {
                "avg_coverage": sum(p["coverage_percentage"] for p in points) / len(points) if points else 0,
                "total_targets": len(points),
            },
        }

    async def _query_risk_trend(self, query: AnalyticsQuery) -> dict[str, Any]:
        target_ids = query.target_ids or await self._get_all_target_ids()
        points = []

        for target_id in target_ids:
            snapshots = await self.db.posture_snapshots.find({
                "target_id": str(target_id),
                "computed_at": {"$gte": query.time_range_start, "$lte": query.time_range_end}
            }).sort("computed_at", 1).to_list(None)

            for s in snapshots:
                points.append({
                    "target_id": str(target_id),
                    "timestamp": s["computed_at"],
                    "score": s["overall_score"],
                    "posture": s["posture_level"],
                    "critical": s["critical_findings_count"],
                    "high": s["high_findings_count"],
                })

        return {
            "data_points": points,
            "aggregations": {
                "total_snapshots": len(points),
            },
        }

    async def _query_finding_distribution(self, query: AnalyticsQuery) -> dict[str, Any]:
        target_ids = query.target_ids or await self._get_all_target_ids()
        points = []

        for target_id in target_ids:
            findings = await self.db.findings.find({
                "target_id": target_id,
                "created_at": {"$gte": query.time_range_start, "$lte": query.time_range_end}
            }).to_list(None)

            severity_counts = {}
            for f in findings:
                sev = f.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            points.append({
                "target_id": str(target_id),
                "total_findings": len(findings),
                "severity_distribution": severity_counts,
            })

        return {
            "data_points": points,
            "aggregations": {
                "total_findings": sum(p["total_findings"] for p in points),
            },
        }

    async def _query_remediation_effectiveness(self, query: AnalyticsQuery) -> dict[str, Any]:
        target_ids = query.target_ids or await self._get_all_target_ids()
        points = []

        for target_id in target_ids:
            findings = await self.db.findings.find({"target_id": target_id}).to_list(None)
            total = len(findings)
            fixed = len([f for f in findings if f.get("status") in ("fixed", "verified")])
            remediated = len([f for f in findings if f.get("status") == "remediated"])
            in_progress = len([f for f in findings if f.get("status") == "in_progress"])

            points.append({
                "target_id": str(target_id),
                "total": total,
                "fixed": fixed,
                "remediated": remediated,
                "in_progress": in_progress,
                "remediation_rate": fixed / total if total > 0 else 0,
            })

        return {
            "data_points": points,
            "aggregations": {
                "avg_remediation_rate": sum(p["remediation_rate"] for p in points) / len(points) if points else 0,
            },
        }

    async def _query_regression_analysis(self, query: AnalyticsQuery) -> dict[str, Any]:
        target_ids = query.target_ids or await self._get_all_target_ids()
        points = []

        for target_id in target_ids:
            runs = await self.db.regression_runs.find({
                "started_at": {"$gte": query.time_range_start, "$lte": query.time_range_end}
            }).to_list(None)

            fixed = len([r for r in runs if r.get("result") == "fixed"])
            regression = len([r for r in runs if r.get("result") == "regression"])
            error = len([r for r in runs if r.get("result") == "error"])

            points.append({
                "target_id": str(target_id),
                "total_runs": len(runs),
                "fixed": fixed,
                "regression": regression,
                "error": error,
                "regression_rate": regression / len(runs) if runs else 0,
            })

        return {
            "data_points": points,
            "aggregations": {
                "total_runs": sum(p["total_runs"] for p in points),
                "avg_regression_rate": sum(p["regression_rate"] for p in points) / len(points) if points else 0,
            },
        }

    async def _query_evidence_quality(self, query: AnalyticsQuery) -> dict[str, Any]:
        target_ids = query.target_ids or await self._get_all_target_ids()
        points = []

        for target_id in target_ids:
            evidence = await self.db.evidence.find({"target_id": target_id}).to_list(None)
            total = len(evidence)
            normalized = len([e for e in evidence if e.get("status") == "normalized"])
            raw = len([e for e in evidence if e.get("status") == "raw"])
            validated = len([e for e in evidence if e.get("status") == "validated"])

            points.append({
                "target_id": str(target_id),
                "total": total,
                "normalized": normalized,
                "raw": raw,
                "validated": validated,
                "quality_score": normalized / total if total > 0 else 0,
            })

        return {
            "data_points": points,
            "aggregations": {
                "avg_quality": sum(p["quality_score"] for p in points) / len(points) if points else 0,
            },
        }

    async def _query_target_comparison(self, query: AnalyticsQuery) -> dict[str, Any]:
        target_ids = query.target_ids
        if len(target_ids) < 2:
            return {"data_points": [], "aggregations": {}}

        points = []
        for target_id in target_ids:
            latest = await self.db.posture_snapshots.find_one(
                {"target_id": str(target_id)},
                sort=[("computed_at", -1)]
            )
            if latest:
                points.append({
                    "target_id": str(target_id),
                    "score": latest["overall_score"],
                    "posture": latest["posture_level"],
                    "critical": latest["critical_findings_count"],
                })

        return {
            "data_points": points,
            "aggregations": {
                "max_score": max(p["score"] for p in points) if points else 0,
                "min_score": min(p["score"] for p in points) if points else 0,
            },
        }

    async def _query_model_performance(self, query: AnalyticsQuery) -> dict[str, Any]:
        target_ids = query.target_ids or await self._get_all_target_ids()
        points = []

        for target_id in target_ids:
            comparisons = await self.db.model_version_comparisons.find({
                "target_id": str(target_id),
                "compared_at": {"$gte": query.time_range_start, "$lte": query.time_range_end}
            }).to_list(None)

            total_new = sum(len(c.get("new_vulnerabilities", [])) for c in comparisons)
            total_fixed = sum(len(c.get("fixed_vulnerabilities", [])) for c in comparisons)
            total_regressions = sum(len(c.get("regressions", [])) for c in comparisons)

            points.append({
                "target_id": str(target_id),
                "comparisons": len(comparisons),
                "new_vulnerabilities": total_new,
                "fixed_vulnerabilities": total_fixed,
                "regressions": total_regressions,
            })

        return {
            "data_points": points,
            "aggregations": {
                "total_comparisons": sum(p["comparisons"] for p in points),
                "total_regressions": sum(p["regressions"] for p in points),
            },
        }

    async def _get_all_target_ids(self) -> list[UUID]:
        cursor = self.db.targets.find({}, {"id": 1})
        return [UUID(doc["id"]) async for doc in cursor]

    async def create_widget(self, widget: DashboardWidget) -> DashboardWidget:
        await self.widgets_collection.insert_one(widget.model_dump())
        return widget

    async def get_widgets(self) -> list[DashboardWidget]:
        cursor = self.widgets_collection.find({})
        return [DashboardWidget(**doc) async for doc in cursor]

    async def create_report(self, report: AnalyticsReport) -> AnalyticsReport:
        await self.reports_collection.insert_one(report.model_dump())
        return report

    async def get_reports(self) -> list[AnalyticsReport]:
        cursor = self.reports_collection.find({})
        return [AnalyticsReport(**doc) async for doc in cursor]

    async def execute_report(self, report_id: UUID) -> dict[str, Any]:
        doc = await self.reports_collection.find_one({"report_id": str(report_id)})
        if not doc:
            raise ValueError(f"Report {report_id} not found")
        report = AnalyticsReport(**doc)

        results = {}
        for widget_id in report.widgets:
            widget_doc = await self.widgets_collection.find_one({"widget_id": str(widget_id)})
            if widget_doc:
                widget = DashboardWidget(**widget_doc)
                query = AnalyticsQuery(
                    query_id=uuid4(),
                    analytics_type=widget.analytics_type,
                    target_ids=widget.target_ids,
                    time_range_start=datetime.utcnow() - timedelta(days=30),
                    time_range_end=datetime.utcnow(),
                    granularity=widget.granularity,
                )
                result = await self.execute_query(query)
                results[str(widget_id)] = result

        return {"report_id": str(report_id), "results": results}