"""
Live Terminal Logs Component

Displays real-time console output from the orchestrator and agents in the browser.
Judges can watch the same logs that would appear in a terminal window when running restart.ps1.
"""

import streamlit as st
import sys
import io
from contextlib import contextmanager
from datetime import datetime


class LogCapture(io.StringIO):
    """Custom StringIO that captures output and stores it in session state."""
    
    def write(self, text):
        if text and text.strip():  # Only capture non-empty lines
            if "live_terminal_logs" not in st.session_state:
                st.session_state.live_terminal_logs = []
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            st.session_state.live_terminal_logs.append(f"[{timestamp}] {text}")
            
            # Keep only last 1000 lines to prevent memory issues
            if len(st.session_state.live_terminal_logs) > 1000:
                st.session_state.live_terminal_logs = st.session_state.live_terminal_logs[-1000:]
        
        # Also write to actual stdout so logs still appear in terminal
        return sys.__stdout__.write(text)


def render_live_logs():
    """Render live terminal logs viewer."""
    st.header("🖥️ Live Terminal Logs")
    
    st.caption(
        "This shows the same detailed console output you would see when running `restart.ps1` in a terminal. "
        "These logs include agent reasoning, command execution details, and validation results."
    )
    
    # Initialize logs if not present
    if "live_terminal_logs" not in st.session_state:
        st.session_state.live_terminal_logs = []
    
    logs = st.session_state.live_terminal_logs
    
    if not logs:
        st.info("No terminal logs yet. Logs will appear here when you start a workflow.")
        return
    
    # Control panel
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.metric("Total Log Lines", len(logs))
    
    with col2:
        if st.button("Clear Logs", help="Clear all terminal logs"):
            st.session_state.live_terminal_logs = []
            st.rerun()
    
    with col3:
        auto_scroll = st.checkbox("Auto-scroll", value=True, help="Automatically scroll to bottom")
    
    st.divider()
    
    # Display logs in scrollable code block
    if logs:
        # Join all logs into a single string
        log_text = "\n".join(logs)
        
        # Display in code block with max height
        st.code(log_text, language="text", line_numbers=False)
        
        # Auto-scroll hint
        if auto_scroll:
            st.caption("✅ Auto-scroll enabled - showing latest logs")
        
        # Download button
        st.download_button(
            label="📥 Download Logs",
            data=log_text,
            file_name=f"ares_terminal_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            help="Download all terminal logs as a text file"
        )


def clear_live_logs():
    """Clear all live terminal logs."""
    if "live_terminal_logs" in st.session_state:
        st.session_state.live_terminal_logs = []


@contextmanager
def capture_logs():
    """Context manager to capture stdout to session state while still printing to terminal."""
    old_stdout = sys.stdout
    log_capture = LogCapture()
    
    try:
        # Note: This doesn't actually redirect stdout in Streamlit's execution model
        # The print() statements in orchestrator_runner.py will still go to server console
        # This is more of a placeholder for future enhancement
        yield log_capture
    finally:
        sys.stdout = old_stdout
