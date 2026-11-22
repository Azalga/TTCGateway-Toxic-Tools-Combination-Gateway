#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modular entry point for the Enterprise Copilot & LLM-as-a-Judge Vulnerability Audit Suite.
Forwards CLI arguments directly to demo_realworld_agent.py at the repository root.
"""
import os
import sys
import runpy

if __name__ == "__main__":
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root_dir = os.path.dirname(parent_dir)
    if root_dir not in sys.path:
        sys.path.insert(0, root_dir)
    target_script = os.path.join(root_dir, "demo_realworld_agent.py")
    runpy.run_path(target_script, run_name="__main__")
