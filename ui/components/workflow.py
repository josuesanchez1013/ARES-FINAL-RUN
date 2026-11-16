"""
Combined Workflow Component for ARES Streamlit UI

Single-page workflow:
1. Upload files
2. Click "Upload & Start Workflow" (single button)
3. Real-time progress with full agent output
4. Auto-advances through all steps

No separate tabs needed - everything flows on one page.
"""

import streamlit as st
import time
from pathlib import Path
import sys
import uuid
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent.parent
UI_DIR = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(UI_DIR) not in sys.path:
    sys.path.insert(0, str(UI_DIR))

from orchestrator_runner import execute_next_step, STEP_DEFINITIONS


def render_workflow_page():
    """Render unified workflow page: upload + progress + execution."""
    
    # Section 1: File Upload
    st.header("📁 Upload STIG Scan Files")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Tool 1 (CKL/CSV)")
        tool1_file = st.file_uploader(
            "Upload Tool 1 output",
            type=["ckl", "csv"],
            key="tool1_uploader",
            help="CKL (XML) or CSV format from any STIG scanner (PreSTIGe, evaluate-STIG, etc.)"
        )
    
    with col2:
        st.subheader("Tool 2 (CKL/CSV)")
        tool2_file = st.file_uploader(
            "Upload Tool 2 output",
            type=["ckl", "csv"],
            key="tool2_uploader",
            help="CKL (XML) or CSV format from any STIG scanner"
        )
    
    # Show uploaded file info
    if tool1_file:
        st.success(f"✅ Tool 1: {tool1_file.name} ({tool1_file.size:,} bytes)")
    if tool2_file:
        st.success(f"✅ Tool 2: {tool2_file.name} ({tool2_file.size:,} bytes)")
    
    # Store files in session state when uploaded
    if tool1_file and tool2_file:
        st.session_state.uploaded_files = {
            "tool1_name": tool1_file.name,
            "tool1_bytes": tool1_file.getvalue(),
            "tool2_name": tool2_file.name,
            "tool2_bytes": tool2_file.getvalue(),
        }
    
    st.divider()
    
    # Section 2: Workflow Controls (only show when NOT running)
    if not st.session_state.workflow_started:
        st.header("🚀 Execute Workflow")
        
        # Check if workflow is locked by another session
        workflow_lock = st.session_state.get("workflow_lock")
        current_session = st.session_state.get("_session_id", str(uuid.uuid4()))
        
        if workflow_lock and workflow_lock.get("session_id") != current_session:
            # Workflow is locked by another user
            lock_info = workflow_lock.get("user_info", "Unknown user")
            lock_time = workflow_lock.get("started_at", "Unknown time")
            st.warning(
                f"⚠️ **Workflow is currently in use**\n\n"
                f"Started by: {lock_info}\n\n"
                f"Started at: {lock_time}\n\n"
                f"Please wait for the current workflow to complete before starting a new one. "
                f"Only one workflow can run at a time to prevent conflicts."
            )
            st.info("💡 **Tip:** Refresh this page in a few minutes to check if the workflow has completed.")
        elif not st.session_state.uploaded_files:
            st.info("👆 Upload both files to begin")
        else:
            # Ready to run
            col_a, col_b = st.columns([3, 1])
            with col_a:
                mode_text = "Mock Data Mode" if st.session_state.demo_mode else "Production Mode"
                st.info(f"✅ Ready to execute")
                st.caption(
                    "**Parser Agent + Gap Identifier:** Production mode only (MCP + Genesis)  \n"
                    f"**Remaining steps:** {mode_text}"
                )
            with col_b:
                if st.button("Upload & Start Workflow", type="primary", use_container_width=True):
                    _start_workflow()
                    st.rerun()
        
        st.divider()
    
    # Show complete execution log when workflow is complete
    if st.session_state.workflow_complete:
        # Release lock on completion
        st.session_state.workflow_lock = None
        
        st.success(f"✅ Workflow complete! ({st.session_state.pipeline_elapsed:.1f}s)")
        
        # Show complete execution log
        st.markdown("### 📋 Complete Execution Log")
        if "all_step_logs" in st.session_state:
            for i, step_def in enumerate(STEP_DEFINITIONS):
                step_name_complete = step_def["name"]
                step_key_complete = step_def["key"]
                
                step_logs = st.session_state.all_step_logs.get(step_key_complete, [])
                if step_logs:
                    st.markdown(f"### ✅ {step_name_complete}")
                    for log in step_logs:
                        level = log.get("level", "info")
                        msg = log.get("message", "")
                        if level == "success":
                            st.markdown(f"✅ {msg}")
                        elif level == "error":
                            st.markdown(f"❌ {msg}")
                        elif level == "warning":
                            st.markdown(f"⚠️ {msg}")
                        elif level == "header":
                            st.markdown(f"### {msg}")
                        else:
                            st.markdown(msg)
                    st.divider()
        
        if st.button("🔄 Reset & Run Again"):
            _reset_workflow()
            st.rerun()
        
        st.divider()
    
    # Section 3: Real-time Progress (only show when workflow started)
    if st.session_state.workflow_started:
        st.header("📊 Pipeline Progress")
        
        # Overall progress bar
        current_step = st.session_state.workflow_step
        progress_pct = (current_step / 6)
        st.progress(progress_pct, text=f"Step {current_step} of 6")
        
        # Execute current step if not complete
        if not st.session_state.workflow_complete:
            step_name = STEP_DEFINITIONS[current_step]["name"]
            
            # Show what's currently processing
            st.info(f"⏳ **Currently processing:** {step_name}")
            
            # Initialize step logs dict if not exists
            if "all_step_logs" not in st.session_state:
                st.session_state.all_step_logs = {}
            
            # Initialize log for THIS step if it doesn't exist (DON'T clear existing logs)
            step_key = STEP_DEFINITIONS[current_step]["key"]
            if step_key not in st.session_state.all_step_logs:
                st.session_state.all_step_logs[step_key] = []
            
            # Show all PREVIOUS steps' logs first
            for i in range(current_step):
                step_def = STEP_DEFINITIONS[i]
                step_name_prev = step_def["name"]
                step_key_prev = step_def["key"]
                
                step_logs = st.session_state.all_step_logs.get(step_key_prev, [])
                if step_logs:
                    st.markdown(f"### ✅ {step_name_prev}")
                    for log in step_logs:
                        level = log.get("level", "info")
                        msg = log.get("message", "")
                        if level == "success":
                            st.markdown(f"✅ {msg}")
                        elif level == "error":
                            st.markdown(f"❌ {msg}")
                        elif level == "warning":
                            st.markdown(f"⚠️ {msg}")
                        elif level == "header":
                            st.markdown(f"### {msg}")
                        else:
                            st.markdown(msg)
                    st.divider()
            
            # Current step header
            st.markdown(f"### ⏳ {step_name}")
            
            # Create live container for current step logs
            current_step_container = st.empty()
            
            # Status container for completion message
            status_container = st.empty()
            
            try:
                # Execute ONE step
                with st.spinner(f"Executing {step_name}..."):
                    # Use mock mode from session state
                    use_mock = st.session_state.demo_mode
                    
                    # Execute the step
                    has_more_steps = execute_next_step(use_mock=use_mock)
                
                # After execution, show current step logs in the container
                with current_step_container.container():
                    step_logs = st.session_state.all_step_logs.get(step_key, [])
                    for log in step_logs:
                        level = log.get("level", "info")
                        msg = log.get("message", "")
                        if level == "success":
                            st.markdown(f"✅ {msg}")
                        elif level == "error":
                            st.markdown(f"❌ {msg}")
                        elif level == "warning":
                            st.markdown(f"⚠️ {msg}")
                        elif level == "header":
                            st.markdown(f"### {msg}")
                        else:
                            st.markdown(msg)
                
                # Show completion message
                duration = st.session_state.step_durations.get(step_key, 0)
                status_container.success(f"✅ {step_name} completed in {duration:.2f}s")
                        
                # Auto-advance to next step by rerunning
                time.sleep(0.5)  # Brief pause to show completion
                st.rerun()
                
            except Exception as e:
                error_msg = str(e)
                error_type = type(e).__name__
                st.error(f"❌ **{step_name} failed:** {error_type}")
                with st.expander("Error Details", expanded=True):
                    st.code(error_msg, language="text")
                st.session_state.workflow_started = False
                st.stop()
        
        # Show step details
        st.subheader("Step Details")
        
        for i, step_def in enumerate(STEP_DEFINITIONS):
            step_name = step_def["name"]
            step_key = step_def["key"]
            step_type = step_def["type"]
            description = step_def["description"]
            
            # Determine status
            if i < current_step:
                status = "✅ Complete"
                duration = st.session_state.step_durations.get(step_key, 0)
                status_text = f"{status} ({duration:.2f}s)"
                expanded = False
            elif i == current_step and not st.session_state.workflow_complete:
                status = "⏳ Running"
                status_text = status
                expanded = True
            else:
                status = "⚪ Pending"
                status_text = status
                expanded = False
            
            # Create expander for each step
            with st.expander(f"**{step_name}** - {status_text}", expanded=expanded):
                st.caption(f"*{description}*")
                st.caption(f"Type: {step_type.upper()}")
                
                # Show logs if step is complete
                if i < current_step:
                    # Show logs for this step
                    step_logs = st.session_state.all_step_logs.get(step_key, [])
                    if step_logs:
                        with st.container():
                            st.markdown("**📋 Execution Log:**")
                            for log in step_logs:
                                level = log.get("level", "info")
                                msg = log.get("message", "")
                                if level == "success":
                                    st.markdown(f"✅ {msg}")
                                elif level == "error":
                                    st.markdown(f"❌ {msg}")
                                elif level == "warning":
                                    st.markdown(f"⚠️ {msg}")
                                elif level == "header":
                                    st.markdown(f"### {msg}")
                                else:
                                    st.markdown(f"{msg}")
                    
                    st.divider()
                    
                    # Show output if step is complete
                    step_output = st.session_state.get(step_key)
                    
                    if step_output:
                        # Show summary based on step type
                        if step_key == "parser_output":
                            tool1_count = len(step_output.get("tool1_findings", []))
                            tool2_count = len(step_output.get("tool2_findings", []))
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Tool 1 Findings", tool1_count)
                            with col2:
                                st.metric("Tool 2 Findings", tool2_count)
                            
                            metadata = step_output.get("metadata", {})
                            if metadata:
                                st.caption(f"**Source:** {metadata.get('source_tools', {}).get('tool1', {}).get('file', 'Unknown')} + {metadata.get('source_tools', {}).get('tool2', {}).get('file', 'Unknown')}")
                                st.caption(f"**Parser:** v{metadata.get('parser_version', 'N/A')}")
                            
                        elif step_key == "identified_gaps":
                            gap_count = len(step_output)
                            st.metric("Gaps Identified", gap_count)
                            
                            if gap_count > 0:
                                # Show sample gaps
                                with st.expander("View Sample Gaps (first 5)"):
                                    for idx, gap in enumerate(step_output[:5]):
                                        st.markdown(f"**{idx+1}.** {gap.get('vuln_id', 'N/A')}: {gap.get('rule_title', 'No title')[:60]}...")
                            
                        elif step_key == "gap_coverage_results":
                            validated_count = len(step_output)
                            st.metric("Gaps Validated", validated_count)
                            
                            # Show CLI commands if has_cli
                            if step_def.get("has_cli") and isinstance(step_output, list) and len(step_output) > 0:
                                with st.expander("View CLI Commands Executed"):
                                    sample = step_output[0]
                                    if "commands_executed" in sample:
                                        st.code("\n".join(sample["commands_executed"]), language="bash")
                                    if "command_outputs" in sample:
                                        st.markdown("**Sample Output:**")
                                        st.code(str(sample["command_outputs"])[:500], language="text")
                        
                        elif step_key == "comparison_output":
                            agreements = len(step_output.get("agreements", []))
                            disagreements = len(step_output.get("disagreements", []))
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Agreements", agreements, delta=None)
                            with col2:
                                st.metric("Disagreements", disagreements, delta=None)
                        
                        elif step_key == "determination_output":
                            resolved_count = len(step_output)
                            st.metric("Disagreements Resolved", resolved_count)
                            
                            # Show sample resolutions
                            if resolved_count > 0:
                                with st.expander("View Sample Resolutions"):
                                    for idx, item in enumerate(step_output[:3]):
                                        st.markdown(f"**{idx+1}.** {item.get('vuln_id', 'N/A')}: {item.get('final_verdict', 'Unknown')}")
                            
                        elif step_key == "final_report":
                            metrics = step_output.get("metrics", {})
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Total Rules", metrics.get("total_rules", 0))
                            with col2:
                                st.metric("Reconciled", metrics.get("total_rules", 0) - metrics.get("requires_review", 0))
                            with col3:
                                st.metric("Needs Review", metrics.get("requires_review", 0))
                        
                        # Show raw data toggle
                        if st.checkbox(f"Show raw JSON output", key=f"raw_{step_key}"):
                            st.json(step_output)
                    else:
                        st.warning("⚠️ No output data available")
                
                elif i == current_step and not st.session_state.workflow_complete:
                    st.info("⏳ Currently processing...")
        
        # Show overall timing
        # Show overall timing (removed from here - it's already shown in workflow complete section)


def _start_workflow():
    """Initialize workflow execution."""
    # Acquire execution lock
    current_session = st.session_state.get("_session_id", str(uuid.uuid4()))
    st.session_state._session_id = current_session
    
    st.session_state.workflow_lock = {
        "session_id": current_session,
        "started_at": datetime.now().isoformat(),
        "user_info": f"Session {current_session[:8]}"
    }
    
    st.session_state.workflow_started = True
    st.session_state.workflow_step = 0
    st.session_state.workflow_complete = False
    st.session_state.pipeline_error = None
    
    # Clear previous results
    st.session_state.parser_output = None
    st.session_state.identified_gaps = None
    st.session_state.gap_coverage_results = None
    st.session_state.comparison_output = None
    st.session_state.determination_output = None
    st.session_state.final_report = None
    st.session_state.step_durations = {}


def _reset_workflow():
    """Reset workflow to initial state."""
    # Release execution lock
    st.session_state.workflow_lock = None
    
    st.session_state.workflow_started = False
    st.session_state.workflow_step = 0
    st.session_state.workflow_complete = False
    st.session_state.pipeline_error = None
    st.session_state.uploaded_files = None
    
    # Clear all results
    st.session_state.parser_output = None
    st.session_state.identified_gaps = None
    st.session_state.gap_coverage_results = None
    st.session_state.comparison_output = None
    st.session_state.determination_output = None
    st.session_state.final_report = None
    st.session_state.step_durations = {}
    st.session_state.pipeline_elapsed = 0
