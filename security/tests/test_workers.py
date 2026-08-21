import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime
from security.workers.tasks import (
    run_analysis_pipeline,
    build_attack_graph,
    generate_regression_test,
    run_regression_test,
    assess_severity,
    update_baselines,
    check_regressions,
    full_analysis_workflow,
)


class TestWorkerTasks:
    @pytest.mark.asyncio
    async def test_run_analysis_pipeline_task_structure(self):
        # Test that task function exists and has correct signature
        assert callable(run_analysis_pipeline)
        assert run_analysis_pipeline.name == "security.workers.tasks.run_analysis_pipeline"

    @pytest.mark.asyncio
    async def test_build_attack_graph_task_structure(self):
        assert callable(build_attack_graph)
        assert build_attack_graph.name == "security.workers.tasks.build_attack_graph"

    @pytest.mark.asyncio
    async def test_generate_regression_test_task_structure(self):
        assert callable(generate_regression_test)
        assert generate_regression_test.name == "security.workers.tasks.generate_regression_test"

    @pytest.mark.asyncio
    async def test_run_regression_test_task_structure(self):
        assert callable(run_regression_test)
        assert run_regression_test.name == "security.workers.tasks.run_regression_test"

    @pytest.mark.asyncio
    async def test_assess_severity_task_structure(self):
        assert callable(assess_severity)
        assert assess_severity.name == "security.workers.tasks.assess_severity"

    @pytest.mark.asyncio
    async def test_update_baselines_task_structure(self):
        assert callable(update_baselines)
        assert update_baselines.name == "security.workers.tasks.update_baselines"

    @pytest.mark.asyncio
    async def test_check_regressions_task_structure(self):
        assert callable(check_regressions)
        assert check_regressions.name == "security.workers.tasks.check_regressions"

    @pytest.mark.asyncio
    async def test_full_analysis_workflow_task_structure(self):
        assert callable(full_analysis_workflow)
        assert full_analysis_workflow.name == "security.workers.tasks.full_analysis_workflow"

    @pytest.mark.asyncio
    async def test_task_retry_config(self):
        # Verify tasks have retry configuration
        assert run_analysis_pipeline.max_retries == 3
        assert run_analysis_pipeline.default_retry_delay == 60
        assert build_attack_graph.max_retries == 3
        assert generate_regression_test.max_retries == 3