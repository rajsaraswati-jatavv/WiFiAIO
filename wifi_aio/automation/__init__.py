"""WiFiAIO automation sub-package.

Provides workflow engine, task scheduling, custom scripting,
batch processing, and operation recording/replay.
"""

from wifi_aio.automation.workflow_engine import WorkflowEngine, WorkflowStep, WorkflowResult
from wifi_aio.automation.task_scheduler import TaskScheduler, ScheduledTask
from wifi_aio.automation.custom_script import CustomScript, ScriptResult
from wifi_aio.automation.batch_processor import BatchProcessor, BatchResult
from wifi_aio.automation.script_recorder import ScriptRecorder, RecordedAction

__all__ = [
    "WorkflowEngine",
    "WorkflowStep",
    "WorkflowResult",
    "TaskScheduler",
    "ScheduledTask",
    "CustomScript",
    "ScriptResult",
    "BatchProcessor",
    "BatchResult",
    "ScriptRecorder",
    "RecordedAction",
]
