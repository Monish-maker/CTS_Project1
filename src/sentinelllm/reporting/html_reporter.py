"""Self-contained HTML report generators."""

import html
import json
from pathlib import Path
from typing import Any

from sentinelllm.core.models import ScanHistory
from sentinelllm.reporting.base import ReportGenerator
from sentinelllm.reporting.data import attack_report_data, security_report_data
from sentinelllm.reporting.json_reporter import _json_default


class HtmlReportGenerator(ReportGenerator):
    """Generate distinct human-readable security and attack journey reports."""

    def generate(self, history: ScanHistory, output_directory: Path) -> Path:
        """Write both HTML projections and return the security report path."""
        output_directory.mkdir(parents=True, exist_ok=True)
        security_path = output_directory / "sentinelllm_security_report.html"
        attack_path = output_directory / "sentinelllm_attack_report.html"
        security_path.write_text(_security_html(security_report_data(history)), encoding="utf-8")
        attack_path.write_text(_attack_html(attack_report_data(history)), encoding="utf-8")
        return security_path


def _page(title: str, subtitle: str, content: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>"
        ":root{--ink:#17201d;--paper:#f4f1e8;--panel:#fff;--accent:#b5412d;"
        "--teal:#176b68;--line:#cbc7bc}*{box-sizing:border-box}"
        "body{margin:0;background:linear-gradient(135deg,#f4f1e8,#e8efe9);"
        "color:var(--ink);font:15px/1.5 Georgia,serif}"
        "header{padding:40px max(5vw,24px);border-bottom:4px solid var(--ink)}"
        "h1,h2,h3{font-family:'Trebuchet MS',sans-serif;letter-spacing:0}"
        "main{max-width:1180px;margin:auto;padding:32px 24px}"
        "section{margin:0 0 32px}table{width:100%;border-collapse:collapse;"
        "background:var(--panel)}th,td{padding:10px;text-align:left;"
        "border:1px solid var(--line);vertical-align:top}th{background:#dce7e1}"
        "article{background:var(--panel);border-left:5px solid var(--accent);"
        "padding:18px;margin:14px 0}code,pre{font-family:Consolas,monospace}"
        "pre{white-space:pre-wrap;max-height:420px;overflow:auto}"
        "details{margin:10px 0}.timeline{border-left:3px solid var(--teal);"
        "padding-left:24px}.muted{color:#53605a}a{color:var(--teal)}"
        ".conversation{background:#f7f5ee;border:1px solid var(--line);"
        "border-radius:4px;padding:10px 14px;margin:10px 0}"
        ".conversation pre{background:#fff;border:1px solid var(--line);padding:8px}"
        ".filters{display:grid;grid-template-columns:2fr 1fr 1fr;gap:10px;margin:16px 0}"
        ".filters input,.filters select{width:100%;padding:9px;border:1px solid var(--line);"
        "background:var(--panel);color:var(--ink);font:inherit}"
        "@media(max-width:700px){table{display:block;overflow:auto}"
        "header{padding:24px}}</style></head><body><header>"
        f"<h1>{html.escape(title)}</h1><p>{html.escape(subtitle)}</p></header>"
        f"<main>{content}</main></body></html>"
    )


def _security_html(data: dict[str, Any]) -> str:
    summary = data["executive_summary"]
    remediation_summary = data["remediation_summary"]
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item['category']))}</td>"
        f"<td>{html.escape(str(item['status']))}</td>"
        f"<td>{item['strategies_evaluated']} / {item['strategies_available']}</td>"
        f"<td>{len(item['verified_findings'])}</td>"
        f"<td>{item['confidence']:.2f}</td></tr>"
        for item in data["owasp_coverage"]
    )
    findings = (
        "".join(
            f"<article id='{item['finding_id']}'>"
            f"<h3>{html.escape(item['title'])}</h3>"
            f"<p>{html.escape(item['description'])}</p>"
            f"<p><strong>Impact:</strong> {html.escape(item['impact'])}</p>"
            "<h4>Missing Security Control</h4>"
            f"<p>{html.escape(item['missing_security_control'])}</p>"
            "<h4>Immediate Containment</h4>"
            f"{_html_list(item['immediate_actions'])}"
            "<h4>Recommended Corrective Measures</h4>"
            f"{_html_list(item['recommended_actions'])}"
            "<h4>How to Validate the Fix</h4>"
            f"{_html_list(item['validation_steps'])}"
            f"<p><strong>OWASP guidance:</strong> {html.escape(item['remediation'])}</p>"
            f"<p>Attack jobs: {html.escape(', '.join(item['job_ids']))}</p></article>"
            for item in data["findings"]
        )
        or "<p>No verified findings were produced. Review category coverage and "
        "inconclusive tests.</p>"
    )
    content = (
        "<section><h2>Executive Summary</h2>"
        f"<p>{html.escape(str(summary['overall_assessment']))}</p>"
        "<p><strong>Total verified vulnerabilities:</strong> "
        f"{summary['total_vulnerabilities']}</p></section>"
        "<section><h2>OWASP 2026 Coverage</h2><table><thead><tr>"
        "<th>Category</th><th>Status</th><th>Strategies</th><th>Verified</th>"
        f"<th>Confidence</th></tr></thead><tbody>{rows}</tbody></table></section>"
        f"<section><h2>Findings</h2>{findings}</section>"
        "<section><h2>Prioritized Remediation Plan</h2>"
        "<h3>Immediate Actions</h3>"
        f"{_html_list(remediation_summary['immediate_actions'])}"
        "<h3>Corrective Measures</h3>"
        f"{_html_list(remediation_summary['recommended_actions'])}"
        "<h3>Post-Fix Validation</h3>"
        f"{_html_list(remediation_summary['validation_steps'])}</section>"
        "<p><a href='sentinelllm_attack_report.html'>Open adaptive attack journey</a></p>"
    )
    return _page("SentinelLLM Security Assessment", "What vulnerabilities were verified?", content)


def _html_list(items: list[str] | tuple[str, ...]) -> str:
    if not items:
        return "<p class='muted'>No actions required for the current verified findings.</p>"
    return "<ol>" + "".join(f"<li>{html.escape(str(item))}</li>" for item in items) + "</ol>"


def _attack_html(data: dict[str, Any]) -> str:
    cards = []
    categories = sorted(
        {str(item["category"]) for item in data["iterations"] if item.get("category")}
    )
    outcomes = sorted(
        {
            str(item["judge_result"]["outcome"])
            for item in data["iterations"]
            if item.get("judge_result")
        }
    )
    for item in data["iterations"]:
        observation = item["response_analysis"] or {}
        judgment = item["judge_result"] or {}
        adaptation = item["adaptation_decision"] or {}
        conversation = item.get("conversation") or {}
        prompt_sent = str(conversation.get("prompt_sent", ""))
        response_received = str(conversation.get("response_received", ""))
        http_status = conversation.get("http_status")
        raw = json.dumps(
            {"request": item["attack_job"]["request"], "response": item["target_response"]},
            indent=2,
            default=_json_default,
        )
        search_text = " ".join(
            str(value)
            for value in (
                item.get("category"),
                item.get("strategy"),
                observation.get("summary"),
                judgment.get("outcome"),
                adaptation.get("decision"),
                adaptation.get("reason"),
            )
        ).lower()
        cards.append(
            "<article class='iteration-card' "
            f"data-category='{html.escape(str(item.get('category', '')))}' "
            f"data-outcome='{html.escape(str(judgment.get('outcome', '')))}' "
            f"data-search='{html.escape(search_text)}'>"
            f"<h3>Iteration {item['iteration']}: "
            f"{html.escape(str(item['strategy']))}</h3>"
            "<p><strong>Observed evidence:</strong> "
            f"{html.escape(str(observation.get('summary', 'No response')))}</p>"
            f"<p><strong>Judge:</strong> {html.escape(str(judgment.get('outcome', 'not judged')))} "
            f"({judgment.get('confidence', 0)})</p>"
            "<p><strong>Decision:</strong> "
            f"{html.escape(str(adaptation.get('decision', 'stop')))}</p>"
            "<p><strong>Next strategy:</strong> "
            f"{html.escape(str(adaptation.get('next_strategy_id', 'none')))}</p>"
            "<p><strong>Concise reason:</strong> "
            f"{html.escape(str(adaptation.get('reason', '')))}</p>"
            "<div class='conversation'>"
            "<p><strong>Prompt sent to model:</strong></p>"
            f"<pre>{html.escape(prompt_sent) or '(empty)'}</pre>"
            f"<p><strong>Response received</strong> (HTTP {html.escape(str(http_status))}):</p>"
            f"<pre>{html.escape(response_received) or '(no response body)'}</pre></div>"
            "<details><summary>Raw request and response (JSON)</summary>"
            f"<pre>{html.escape(raw)}</pre></details></article>"
        )
    stats = data["attack_statistics"]
    category_options = "".join(
        f"<option value='{html.escape(item)}'>{html.escape(item)}</option>" for item in categories
    )
    outcome_options = "".join(
        f"<option value='{html.escape(item)}'>{html.escape(item)}</option>" for item in outcomes
    )
    transitions = "".join(
        "<tr>"
        f"<td>{html.escape(str(item['previous_strategy_id']))}</td>"
        f"<td>{html.escape(str(item['next_strategy_id']))}</td>"
        f"<td>{html.escape(str(item['hypothesis_id']))}</td>"
        f"<td>{html.escape(str(item['decision']))}</td>"
        f"<td>{html.escape(str(item['reason']))}</td>"
        "</tr>"
        for item in data["strategy_transitions"]
    )
    content = (
        "<section><h2>Adaptive Behavior Verification</h2>"
        f"<pre>{html.escape(json.dumps(stats, indent=2))}</pre></section>"
        "<section><h2>Iteration Timeline</h2>"
        "<div class='filters'><input id='timeline-search' type='search' "
        "aria-label='Search attack timeline' placeholder='Search timeline'>"
        "<select id='category-filter' aria-label='Filter by category'>"
        f"<option value=''>All categories</option>{category_options}</select>"
        "<select id='outcome-filter' aria-label='Filter by outcome'>"
        f"<option value=''>All outcomes</option>{outcome_options}</select></div>"
        f"<div class='timeline'>{''.join(cards)}</div></section>"
        "<section><h2>Before / After Strategy Comparison</h2><table><thead><tr>"
        "<th>Previous Strategy</th><th>Next Strategy</th><th>Hypothesis</th>"
        "<th>Decision</th><th>Observed Result / Reason</th></tr></thead>"
        f"<tbody>{transitions}</tbody></table></section>"
        "<section><h2>Strategy Statistics</h2>"
        f"<pre>{html.escape(json.dumps(data['strategy_statistics'], indent=2))}</pre></section>"
        "<p><a href='sentinelllm_security_report.html'>Open security assessment</a></p>"
        "<script>"
        "const q=document.getElementById('timeline-search');"
        "const c=document.getElementById('category-filter');"
        "const o=document.getElementById('outcome-filter');"
        "function filterTimeline(){const text=q.value.toLowerCase();"
        "document.querySelectorAll('.iteration-card').forEach(card=>{"
        "card.hidden=!(card.dataset.search.includes(text)&&"
        "(!c.value||card.dataset.category===c.value)&&"
        "(!o.value||card.dataset.outcome===o.value));});}"
        "[q,c,o].forEach(control=>control.addEventListener('input',filterTimeline));"
        "</script>"
    )
    return _page(
        "SentinelLLM Adaptive Attack Journey",
        "How the scanner responded to observed target behavior",
        content,
    )
