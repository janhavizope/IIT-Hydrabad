import os
import sys

# Add the project root to sys.path
project_root = r"C:\Users\janhavi\OneDrive\Documents\IIT Hyderabad Hackathon\IIT Project"
sys.path.insert(0, project_root)

from app.services.dynamic.behavior_engine import BehaviorEngine

def test_database_access():
    engine = BehaviorEngine()
    
    # 1. Simulate the normalized event that would come from instrumentation.py
    # after the frida agent intercepts a SQLite rawQuery
    mock_events = [{
        "timestamp": "06-03 12:00:00.000",
        "tag": "Frida-Instr",
        "pid": "frida",
        "level": "I",
        "message": "SQLite Query: SELECT * FROM users",
        "event_type": "database_access",
    }]
    
    # Run the behavior engine analyze (this represents steps 1-3)
    risk_output = engine.analyze(mock_events)
    
    # Generate summary (this represents step 4: Final report output)
    summary = engine.generate_summary(mock_events, risk_output)
    
    print("=== VALIDATION SCRIPT RESULTS ===")
    
    # Prove 1: Event count increment
    event_counts = risk_output.get("event_counts", {})
    db_count = event_counts.get("database_access", 0)
    print(f"1. Event count increment: database_access count = {db_count}")
    assert db_count == 1, "Event count should be 1"
    
    # Prove 2: Risk contribution
    risk_score = risk_output.get("risk_score", 0)
    print(f"2. Risk contribution: risk_score = {risk_score}")
    assert risk_score >= 5, "Risk score should be at least 5 for a database access event"
    
    # Prove 3: Evidence entry
    evidence = risk_output.get("evidence", [])
    print("3. Evidence entries:")
    for ev in evidence:
        print(f"   - {ev}")
    assert any("database" in ev.lower() for ev in evidence), "Should contain database evidence"
    
    # Prove 4: Final report output
    print("\n4. Final Report (Summary) Output:")
    print(f"   - Summary Text: {summary.get('summary')}")
    print(f"   - Top Risks: {summary.get('top_risks')}")
    print("=================================")

if __name__ == "__main__":
    test_database_access()
