# Tests for Scheduler Functionality

"""Test RedOS continuous scheduling across all schedule types."""

import asyncio
from redos.scheduler import ScheduleManager


async def test_all_schedule_types():
    """Test that all schedule types can be created and triggered."""
    
    org_id = "org_456"
    scheduler = ScheduleManager(org_id=org_id)
    
    # Test hourly schedule
    hourly = await scheduler.generate_campaigns(
        schedule_type="hourly",
        targets_filter="recently_active",
        campaigns=["quick_gates"],
        concurrency=2,
    )
    print(f"✅ Hourly: {len(hourly)} campaigns generated")
    
    # Test daily schedule
    daily = await scheduler.generate_campaigns(
        schedule_type="daily",
        targets_filter="all",
        campaigns=["full_assessment"],
        concurrency=4,
    )
    print(f"✅ Daily: {len(daily)} campaigns generated")
    
    # Test weekly schedule
    weekly = await scheduler.generate_campaigns(
        schedule_type="weekly",
        targets_filter="all",
        campaigns=["comprehensive_assessment"],
        concurrency=6,
    )
    print(f"✅ Weekly: {len(weekly)} campaigns generated")
    
    # Test on_deployment trigger
    await scheduler.trigger(
        schedule_type="on_deployment",
        campaign_type="regression_gate",
        deployment_id="deploy_test_001",
    )
    print("✅ On deployment trigger sent")
    
    # Test on_model_change trigger
    await scheduler.trigger(
        schedule_type="on_model_change",
        campaign_type="model_switch_scan",
        old_model="gpt-4o",
        new_model="gpt-4o-mini",
    )
    print("✅ On model change trigger sent")
    
    # Test on_prompt_change trigger
    await scheduler.trigger(
        schedule_type="on_prompt_change",
        campaign_type="prompt_injection_scan",
        old_prompt_version="v1.2",
        new_prompt_version="v1.3",
    )
    print("✅ On prompt change trigger sent")
    
    # Test on_tool_change trigger
    await scheduler.trigger(
        schedule_type="on_tool_change",
        campaign_type="tool_capability_scan",
        old_tool_version="v2.1",
        new_tool_version="v2.2",
    )
    print("✅ On tool change trigger sent")
    
    # Test on_rag_update trigger
    await scheduler.trigger(
        schedule_type="on_rag_update",
        campaign_type="rag_effectiveness_scan",
        old_index_version="v1.2",
        new_index_version="v1.3",
    )
    print("✅ On RAG update trigger sent")
    
    # Test ci_event trigger
    await scheduler.trigger(
        schedule_type="ci_event",
        campaign_type="ci_gate",
        pipeline_id="github_actions_001",
        pr_number=123,
    )
    print("✅ CI event trigger sent")
    
    print("\n✅ All schedule types tested successfully")


if __name__ == "__main__":
    asyncio.run(test_all_schedule_types())