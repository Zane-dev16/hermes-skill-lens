"""Host VALID_HOOKS fallback fixture.

Copied verbatim from ``VALID_HOOKS`` in
``/usr/local/lib/hermes-agent/hermes_cli/plugins.py`` (set literal begins at
line 161; entries below cite their source lines). Used ONLY when the real
module is not importable in the test environment — conftest prefers the live
import and asserts equality against this literal whenever both are
available, so drift between host and fixture fails loudly.

Citations (plugins.py @ Hermes 0.20.x tree):
  - "pre_tool_call"                     line ~162
  - "post_tool_call"                    line ~163
  - "transform_terminal_output"         line ~164
  - "transform_tool_result"             line ~165
  - "transform_llm_output"              line ~168
  - "pre_llm_call", "post_llm_call"     lines ~169-170
  - stream observers                    lines ~174-177
    ("on_stream_start", "on_stream_delta", "on_stream_end",
     "on_interim_message")
  - "pre_verify"                        line ~186
  - "pre_api_request", "post_api_request",
    "api_request_error"                 lines ~187-189
  - "transform_api_error_classification" line ~219
  - session hooks                       lines ~220-223
    ("on_session_start", "on_session_end", "on_session_finalize",
     "on_session_reset")
  - "on_skill_lifecycle"                line ~225
  - "subagent_start", "subagent_stop"   lines ~226-227
  - "pre_gateway_dispatch"              line ~251
  - approval hooks                      lines ~265-266
    ("pre_approval_request", "post_approval_response")
  - "pre_transcription"                 line ~281
  - kanban hooks                        lines ~309-311, ~357-368
    ("kanban_task_claimed", "kanban_task_completed", "kanban_task_blocked",
     "on_kanban_worker_spawned", "on_kanban_worker_exited",
     "on_kanban_worker_stale_claim", "on_kanban_task_updated",
     "on_kanban_dispatch_tick")
  - "gateway_platform_event"            line ~384
  - "pre_command"                       line ~408
"""

FALLBACK_VALID_HOOKS: frozenset[str] = frozenset(
    {
        "pre_tool_call",
        "post_tool_call",
        "transform_terminal_output",
        "transform_tool_result",
        "transform_llm_output",
        "pre_llm_call",
        "post_llm_call",
        "on_stream_start",
        "on_stream_delta",
        "on_stream_end",
        "on_interim_message",
        "pre_verify",
        "pre_api_request",
        "post_api_request",
        "api_request_error",
        "transform_api_error_classification",
        "on_session_start",
        "on_session_end",
        "on_session_finalize",
        "on_session_reset",
        "on_skill_lifecycle",
        "subagent_start",
        "subagent_stop",
        "pre_gateway_dispatch",
        "pre_approval_request",
        "post_approval_response",
        "pre_transcription",
        "kanban_task_claimed",
        "kanban_task_completed",
        "kanban_task_blocked",
        "on_kanban_worker_spawned",
        "on_kanban_worker_exited",
        "on_kanban_worker_stale_claim",
        "on_kanban_task_updated",
        "on_kanban_dispatch_tick",
        "gateway_platform_event",
        "pre_command",
    }
)
