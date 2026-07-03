"""
Paper-ready reporting — tables, figures, LaTeX output.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from datetime import datetime
import json
from pathlib import Path


class ReportGenerator:
    """Generate paper-ready reports from evaluation results."""
    
    def __init__(self, output_dir: str = "./results"):
        self.output_dir = Path(output_dir)
        self.tables_dir = self.output_dir / "tables"
        self.figures_dir = self.output_dir / "figures"
        self.tables_dir.mkdir(parents=True, exist_ok=True)
        self.figures_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_summary_table(
        self,
        results: Dict[str, Any],
        format: str = "latex"
    ) -> str:
        """Generate summary table of results per model × attack category."""
        
        per_model = results.get("per_model", {})
        per_category = results.get("per_category", {})
        
        if format == "latex":
            return self._summary_latex(per_model, per_category)
        elif format == "markdown":
            return self._summary_markdown(per_model, per_category)
        elif format == "csv":
            return self._summary_csv(per_model, per_category)
        return ""
    
    def _summary_latex(
        self,
        per_model: Dict[str, Any],
        per_category: Dict[str, Any]
    ) -> str:
        """Generate LaTeX table."""
        lines = []
        lines.append("\\begin{table}[htbp]")
        lines.append("\\centering")
        lines.append("\\caption{CoT Red Teaming Results}")
        lines.append("\\label{tab:cot-results}")
        lines.append("\\begin{tabular}{lccc}")
        lines.append("\\toprule")
        lines.append("Model & Success Rate & Evasion Rate & Avg Monitor Conf. \\\\")
        lines.append("\\midrule")
        
        for model_id, metrics in per_model.items():
            sr = metrics.get("success_rate", 0.0) * 100
            er = metrics.get("evasion_rate", 0.0) * 100
            mc = metrics.get("avg_monitor_confidence", 0.0)
            # Escape underscores in model names for LaTeX
            model_clean = model_id.replace("_", "\\_")
            lines.append(f"{model_clean} & {sr:.1f}\\% & {er:.1f}\\% & {mc:.3f} \\\\")
        
        lines.append("\\bottomrule")
        lines.append("\\end{tabular}")
        lines.append("\\end{table}")
        
        return "\n".join(lines)
    
    def _summary_markdown(
        self,
        per_model: Dict[str, Any],
        per_category: Dict[str, Any]
    ) -> str:
        """Generate Markdown table."""
        lines = []
        lines.append("## CoT Red Teaming Results")
        lines.append("")
        lines.append("### Per-Model Summary")
        lines.append("| Model | Success Rate | Evasion Rate | Avg Monitor Confidence |")
        lines.append("|-------|-------------|--------------|------------------------|")
        
        for model_id, metrics in per_model.items():
            sr = metrics.get("success_rate", 0.0) * 100
            er = metrics.get("evasion_rate", 0.0) * 100
            mc = metrics.get("avg_monitor_confidence", 0.0)
            lines.append(f"| {model_id} | {sr:.1f}% | {er:.1f}% | {mc:.3f} |")
        
        lines.append("")
        lines.append("### Per-Category Summary")
        lines.append("| Category | Count | Success Rate | Evasion Rate |")
        lines.append("|----------|-------|-------------|--------------|")
        
        for cat, metrics in per_category.items():
            count = metrics.get("count", 0)
            sr = metrics.get("success_rate", 0.0) * 100
            er = metrics.get("evasion_rate", 0.0) * 100
            lines.append(f"| {cat} | {count} | {sr:.1f}% | {er:.1f}% |")
        
        return "\n".join(lines)
    
    def _summary_csv(
        self,
        per_model: Dict[str, Any],
        per_category: Dict[str, Any]
    ) -> str:
        """Generate CSV."""
        lines = ["model,success_rate,evasion_rate,avg_monitor_confidence"]
        for model_id, metrics in per_model.items():
            sr = metrics.get("success_rate", 0.0)
            er = metrics.get("evasion_rate", 0.0)
            mc = metrics.get("avg_monitor_confidence", 0.0)
            lines.append(f"{model_id},{sr},{er},{mc}")
        return "\n".join(lines)
    
    def generate_report(
        self,
        eval_result: Any,
        format: str = "markdown"
    ) -> str:
        """Generate full report from eval result."""
        
        summary = eval_result.summary if hasattr(eval_result, 'summary') else eval_result.get("summary", {})
        
        report = []
        
        # Header
        report.append(f"# CoT Red Teaming Report")
        report.append(f"**Run ID:** {eval_result.run_id if hasattr(eval_result, 'run_id') else 'N/A'}")
        report.append(f"**Date:** {datetime.now().isoformat()}")
        report.append("")
        
        # Overall metrics
        report.append("## Overall Metrics")
        report.append(f"- Total attacks: {summary.get('total_attacks', 0)}")
        report.append(f"- Successful attacks: {summary.get('successful_attacks', 0)}")
        report.append(f"- Attack success rate: {summary.get('attack_success_rate', 0.0)*100:.1f}%")
        report.append(f"- Evasion rate: {summary.get('evasion_rate', 0.0)*100:.1f}%")
        report.append(f"- Avg monitor confidence: {summary.get('avg_monitor_confidence', 0.0):.3f}")
        report.append("")
        
        # Per-model table
        report.append(self._summary_markdown(
            summary.get("per_model", {}),
            summary.get("per_category", {})
        ))
        
        return "\n".join(report)
    
    def save_report(
        self,
        eval_result: Any,
        format: str = "markdown"
    ) -> str:
        """Save report to file."""
        report = self.generate_report(eval_result, format)
        ext = "tex" if format == "latex" else "md" if format == "markdown" else "csv"
        path = self.tables_dir / f"report_{eval_result.run_id}.{ext}"
        with open(path, "w") as f:
            f.write(report)
        return str(path)