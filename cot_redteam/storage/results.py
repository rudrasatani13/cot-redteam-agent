"""
Results storage — SQLite + Parquet backends.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from datetime import datetime
import json
import sqlite3
from pathlib import Path
from cot_redteam.core.types import AttackResult, EvalResult


class ResultsStore:
    """Store and query evaluation results."""
    
    def __init__(self, db_path: str = "./results/cot_redteam.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                config TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                summary TEXT,
                artifacts_hash TEXT
            );
            
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                attack_name TEXT NOT NULL,
                attack_category TEXT NOT NULL,
                model TEXT NOT NULL,
                prompt TEXT,
                response TEXT,
                cot TEXT,
                success INTEGER NOT NULL,
                severity TEXT,
                evidence TEXT,
                metrics TEXT,
                monitor_results TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );
            
            CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
            CREATE INDEX IF NOT EXISTS idx_results_model ON results(model);
            CREATE INDEX IF NOT EXISTS idx_results_attack ON results(attack_name);
            CREATE INDEX IF NOT EXISTS idx_results_category ON results(attack_category);
            
            CREATE TABLE IF NOT EXISTS model_registry (
                model_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_checked TEXT,
                metadata TEXT
            );
        """)
        conn.commit()
        conn.close()
    
    def save_run(self, eval_result: EvalResult) -> None:
        """Save an evaluation run and all its results."""
        conn = sqlite3.connect(self.db_path)
        
        # Save run
        conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?, ?)",
            (
                eval_result.run_id,
                json.dumps(eval_result.config_snapshot, default=str),
                eval_result.started_at.isoformat() if eval_result.started_at else None,
                eval_result.completed_at.isoformat() if eval_result.completed_at else None,
                json.dumps(eval_result.summary, default=str),
                eval_result.artifacts_hash,
            )
        )
        
        # Save results
        for r in eval_result.attack_results:
            conn.execute(
                "INSERT INTO results (run_id, attack_name, attack_category, model, prompt, response, cot, success, severity, evidence, metrics, monitor_results, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    eval_result.run_id,
                    r.attack_prompt.attack_config.name,
                    r.attack_prompt.attack_config.category.value,
                    r.model_response.model_config.full_id if r.model_response.model_config else None,
                    r.attack_prompt.prompt,
                    r.model_response.full_response,
                    r.model_response.cot,
                    int(r.success),
                    r.severity.value if r.severity else None,
                    json.dumps(r.evidence, default=str),
                    json.dumps(r.metrics, default=str),
                    json.dumps(r.monitor_results, default=str),
                    r.timestamp.isoformat(),
                )
            )
        
        conn.commit()
        conn.close()
    
    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Get a run by ID."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        conn.close()
        
        if row:
            return {
                "run_id": row["run_id"],
                "config": json.loads(row["config"]),
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "summary": json.loads(row["summary"]) if row["summary"] else {},
                "artifacts_hash": row["artifacts_hash"],
            }
        return None
    
    def get_results(self, run_id: str) -> List[Dict[str, Any]]:
        """Get all results for a run."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM results WHERE run_id = ?", (run_id,)).fetchall()
        conn.close()
        
        results = []
        for row in rows:
            results.append({
                "id": row["id"],
                "run_id": row["run_id"],
                "attack_name": row["attack_name"],
                "attack_category": row["attack_category"],
                "model": row["model"],
                "prompt": row["prompt"],
                "response": row["response"],
                "cot": row["cot"],
                "success": bool(row["success"]),
                "severity": row["severity"],
                "evidence": json.loads(row["evidence"]) if row["evidence"] else [],
                "metrics": json.loads(row["metrics"]) if row["metrics"] else {},
                "monitor_results": json.loads(row["monitor_results"]) if row["monitor_results"] else {},
                "timestamp": row["timestamp"],
            })
        return results
    
    def list_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent runs."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT run_id, started_at, completed_at, summary FROM runs ORDER BY started_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        
        runs = []
        for row in rows:
            summary = json.loads(row["summary"]) if row["summary"] else {}
            runs.append({
                "run_id": row["run_id"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "total_attacks": summary.get("total_attacks", 0),
                "success_rate": summary.get("attack_success_rate", 0.0),
            })
        return runs
    
    def compare_runs(self, run_ids: List[str]) -> Dict[str, Any]:
        """Compare metrics across multiple runs."""
        comparison = {}
        for run_id in run_ids:
            run = self.get_run(run_id)
            if run:
                comparison[run_id] = run.get("summary", {})
        return comparison
    
    def query_results(
        self,
        model: Optional[str] = None,
        attack_category: Optional[str] = None,
        attack_name: Optional[str] = None,
        success_only: bool = False,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query results with filters."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        
        query = "SELECT * FROM results WHERE 1=1"
        params = []
        
        if model:
            query += " AND model = ?"
            params.append(model)
        if attack_category:
            query += " AND attack_category = ?"
            params.append(attack_category)
        if attack_name:
            query += " AND attack_name = ?"
            params.append(attack_name)
        if success_only:
            query += " AND success = 1"
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        rows = conn.execute(query, params).fetchall()
        conn.close()
        
        results = []
        for row in rows:
            results.append({
                "run_id": row["run_id"],
                "attack_name": row["attack_name"],
                "attack_category": row["attack_category"],
                "model": row["model"],
                "success": bool(row["success"]),
                "severity": row["severity"],
                "metrics": json.loads(row["metrics"]) if row["metrics"] else {},
            })
        return results