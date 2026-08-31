from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.audit.anonymization import anonymize_events, anonymize_findings, anonymize_ip, anonymize_observations, scrub_text
from app.audit.anonymization_config import load_terms
from app.audit.presentation import SEVERITIES, build_audit_view, prepare_findings
from app.storage.repositories import AuditRepository
from app.utils.json import dumps, loads
from app.utils.time import iso_now


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Neto Kube Auditor Report</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
@page{size:A4;margin:12mm 12mm 14mm;@bottom-right{content:"Page " counter(page) " of " counter(pages);font-size:9px;color:#64748b}@bottom-left{content:"Neto Kube Auditor";font-size:9px;color:#64748b}}
*{box-sizing:border-box}body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:0;color:#182033;background:#edf1f6;line-height:1.45}.cover{background:#101827;color:white;padding:32px 40px 46px;border-bottom:5px solid #2563eb}.cover h1{font-size:30px;margin:0 0 8px}.cover p{margin:4px 0;color:#dbe4ef}.wrap{max-width:1240px;margin:0 auto;padding:20px}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-top:-42px}.metric{background:white;border:1px solid #d8dee8;border-radius:6px;padding:13px;box-shadow:0 10px 24px rgba(22,32,51,.1)}.metric span{display:block;color:#697386;font-size:10px;text-transform:uppercase}.metric strong{font-size:25px;color:#172033}.tabs{display:flex;gap:4px;margin:18px 0 0;border-bottom:1px solid #cbd5e1;overflow-x:auto}.tab-button{border:0;border-bottom:3px solid transparent;background:transparent;color:#475569;padding:10px 13px;font-weight:700;cursor:pointer;white-space:nowrap}.tab-button.active{color:#1d4ed8;border-bottom-color:#2563eb}.tab-panel{display:none}.tab-panel.active{display:block}.section{background:white;border:1px solid #d8dee8;border-radius:6px;padding:16px;margin:14px 0;box-shadow:0 7px 18px rgba(22,32,51,.05)}.section h2{font-size:18px;margin:0 0 10px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.chart{border:1px solid #d8dee8;border-radius:6px;padding:14px}.chart h3{font-size:14px;margin:0 0 10px}.bar{display:grid;grid-template-columns:135px 1fr 38px;align-items:center;gap:8px;margin:7px 0;font-size:11px}.track{height:9px;border-radius:8px;background:#e5eaf2;overflow:hidden}.fill{height:100%;background:#2563eb}.fill.Critical{background:#dc2626}.fill.High{background:#f97316}.fill.Medium{background:#f59e0b}.fill.Low{background:#0284c7}.fill.Info{background:#64748b}.controls{display:grid;grid-template-columns:minmax(220px,2fr) repeat(4,minmax(120px,1fr));gap:8px;margin-bottom:10px}.controls input,.controls select{width:100%;border:1px solid #cbd5e1;border-radius:5px;padding:9px;background:white;color:#172033}.result-count{font-size:12px;color:#64748b;margin:6px 0}.table-scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;max-width:100%;table-layout:fixed;font-size:11px}th,td{border-bottom:1px solid #e3e8f0;padding:7px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}th{background:#f1f5f9;color:#3b4556;font-size:10px;text-transform:uppercase}.findings-table th:nth-child(1){width:11%}.findings-table th:nth-child(2){width:12%}.findings-table th:nth-child(3){width:24%}.findings-table th:nth-child(4){width:17%}.findings-table th:nth-child(5){width:36%}.events-table th:nth-child(1){width:18%}.events-table th:nth-child(2){width:10%}.events-table th:nth-child(3){width:17%}.events-table th:nth-child(4){width:15%}.events-table th:nth-child(5){width:40%}.badge{display:inline-block;border-radius:9px;padding:2px 6px;font-weight:700;font-size:9px}.Critical{color:#991b1b}.High{color:#b45309}.Medium{color:#92400e}.Low{color:#0369a1}.Info{color:#475569}.badge.Critical{background:#fee2e2}.badge.High{background:#ffedd5}.badge.Medium{background:#fef3c7}.badge.Low{background:#e0f2fe}.badge.Info{background:#e2e8f0}.badge.Current{background:#dcfce7;color:#166534}.badge.Review{background:#fef3c7;color:#92400e}.badge.Historical{background:#e2e8f0;color:#475569}.resource,.finding-id{font-family:Consolas,monospace;color:#334155;font-size:10px}.detail{margin-top:5px;color:#475569}.evidence{margin-top:6px;padding:6px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;font-family:Consolas,monospace;font-size:9px;white-space:pre-wrap;max-height:150px;overflow:auto}.empty{color:#697386;background:#f8fafc;border:1px dashed #cbd5e1;border-radius:5px;padding:12px}.incident-resources{font-family:Consolas,monospace;font-size:9px;color:#475569}.method-list{columns:2;column-gap:28px}.method-list li{margin-bottom:7px}.hidden{display:none!important}thead{display:table-header-group}tr{break-inside:avoid}
@media(max-width:760px){.wrap{padding:12px}.cover{padding:24px 18px}.summary{margin-top:10px}.grid{grid-template-columns:1fr}.controls{grid-template-columns:1fr 1fr}.controls input{grid-column:1/-1}}
@media print{body{background:white}.wrap{padding:0}.cover{padding:18px}.summary{margin:10px 0;grid-template-columns:repeat(4,1fr)}.tabs,.controls,.result-count,.table-pagination,details summary{display:none}.tab-panel{display:block!important}.pagination-hidden{display:table-row!important}.section{box-shadow:none;padding:10px;break-before:page}.tab-panel:first-of-type .section:first-child{break-before:auto}.grid{grid-template-columns:1fr 1fr}.evidence,details .evidence{display:block;max-height:none;overflow:visible}table{font-size:8px}th,td{padding:4px}th{font-size:7px}.badge{font-size:7px}.resource,.finding-id{font-size:7px}.method-list{columns:1}}
.table-pagination{display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin:10px 0 2px}.table-pagination span{font-size:11px;color:#64748b;margin-right:4px}.table-pagination button{border:1px solid #cbd5e1;border-radius:4px;background:white;color:#334155;min-width:29px;padding:4px 7px;font-size:11px;cursor:pointer}.table-pagination button:hover{border-color:#2563eb;color:#1d4ed8}.table-pagination button.active{background:#2563eb;border-color:#2563eb;color:white}.pagination-hidden{display:none}
.tab-button[data-tab="history"],#tab-history{display:none!important}
</style></head><body>
<div class="cover"><h1>Neto Kube Auditor</h1><p>Kubernetes / OpenShift technical audit report</p><p>Cluster: <b>{{ cluster_name }}</b> &nbsp; Generated: {{ generated_at }} &nbsp; {% if anonymized %}Anonymized{% else %}Internal names visible{% endif %}</p></div>
<main class="wrap">
<section class="summary">
<div class="metric"><span>Current findings</span><strong>{{ summary.current_findings }}</strong></div><div class="metric"><span>Problem pods</span><strong>{{ summary.problematic_pods }}</strong></div><div class="metric"><span>Critical</span><strong class="Critical">{{ summary.findings_by_severity.get('Critical',0) }}</strong></div><div class="metric"><span>High</span><strong class="High">{{ summary.findings_by_severity.get('High',0) }}</strong></div><div class="metric"><span>Review</span><strong>{{ summary.review_findings }}</strong></div><div class="metric"><span>Historical</span><strong>{{ summary.historical_findings }}</strong></div><div class="metric"><span>Current incidents</span><strong>{{ summary.current_incidents }}</strong></div><div class="metric"><span>Events last hour</span><strong>{{ summary.events_last_hour }}</strong></div>
</section>
<nav class="tabs" aria-label="Report sections"><button class="tab-button active" data-tab="overview">Overview</button><button class="tab-button" data-tab="findings">Findings</button><button class="tab-button" data-tab="incidents">Incidents</button><button class="tab-button" data-tab="events">Events</button><button class="tab-button" data-tab="inventory">Inventory</button><button class="tab-button" data-tab="history">History</button><button class="tab-button" data-tab="pods">Pods</button><button class="tab-button" data-tab="methodology">Methodology</button></nav>
<section class="tab-panel active" id="tab-overview"><div class="section"><h2>Executive summary</h2><p>{{ executive_summary }}</p></div><div class="section grid"><div class="chart"><h3>Current findings by severity</h3>{% for item in severity_chart_items %}<div class="bar"><span>{{ item.label }}</span><div class="track"><div class="fill {{ item.label }}" style="width:{{ item.width }}%"></div></div><b>{{ item.count }}</b></div>{% endfor %}</div><div class="chart"><h3>Current findings by category</h3>{% for item in category_chart_items %}<div class="bar"><span>{{ item.label }}</span><div class="track"><div class="fill" style="width:{{ item.width }}%"></div></div><b>{{ item.count }}</b></div>{% else %}<p class="empty">No current categories.</p>{% endfor %}</div></div><div class="section"><h2>Current priority findings</h2><table class="findings-table"><thead><tr><th>Severity</th><th>Status</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead><tbody>{% for f in priority_findings %}<tr><td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td><td><span class="badge {{ f.temporal_status }}">{{ f.temporal_status }}</span></td><td class="resource">{{ f.resource }}{% if f.pod_scope %}<div class="detail">{{ f.pod_scope }}</div>{% endif %}</td><td><b>{{ f.title }}</b><div class="finding-id">{{ f.finding_id }}</div></td><td>{{ f.recommendation }}</td></tr>{% else %}<tr><td colspan="5" class="empty">No current Critical or High findings.</td></tr>{% endfor %}</tbody></table></div></section>
<section class="tab-panel" id="tab-findings"><div class="section"><h2>Findings register</h2><div class="controls"><input id="finding-search" type="search" placeholder="Search resource, title, evidence or recommendation"><select id="finding-severity"><option value="">All severities</option>{% for value in filter_options.severities %}<option>{{ value }}</option>{% endfor %}</select><select id="finding-status"><option value="">All statuses</option><option>Current</option><option>Review</option><option>Historical</option></select><select id="finding-category"><option value="">All categories</option>{% for value in filter_options.categories %}<option>{{ value }}</option>{% endfor %}</select><select id="finding-namespace"><option value="">All namespaces</option>{% for value in filter_options.namespaces %}<option>{{ value }}</option>{% endfor %}</select></div><div class="result-count"><span id="finding-visible-count">{{ findings|length }}</span> of {{ findings|length }} findings</div><div class="table-scroll"><table class="findings-table"><thead><tr><th>Severity</th><th>Status</th><th>Resource</th><th>Finding</th><th>Assessment</th></tr></thead><tbody id="finding-rows">{% for f in findings %}<tr data-severity="{{ f.severity }}" data-status="{{ f.temporal_status }}" data-category="{{ f.category }}" data-namespace="{{ f.namespace or '-' }}" data-search="{{ (f.resource ~ ' ' ~ f.title ~ ' ' ~ f.description ~ ' ' ~ f.recommendation ~ ' ' ~ f.evidence_json)|lower|e }}"><td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td><td><span class="badge {{ f.temporal_status }}">{{ f.temporal_status }}</span>{% if f.signal_observed_at %}<div class="detail">{{ f.signal_observed_at }}</div>{% endif %}</td><td class="resource">{{ f.resource }}{% if f.pod_scope %}<div class="detail">{{ f.pod_scope }}</div>{% endif %}</td><td><b>{{ f.title }}</b><div class="finding-id">{{ f.finding_id }}</div><div class="detail">{{ f.description }}</div></td><td><b>Recommendation:</b> {{ f.recommendation }}<div class="detail">{{ f.freshness_reason }}</div>{% if f.evidence_obj %}<details><summary>Evidence</summary><pre class="evidence">{{ f.evidence_json }}</pre></details>{% endif %}</td></tr>{% endfor %}</tbody></table></div></div></section>
<section class="tab-panel" id="tab-incidents"><div class="section"><h2>Correlated incidents</h2><p>Repeated log signatures affecting multiple resources in the same time window are grouped here to expose shared causes.</p><table><thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Time window</th><th>Suspected cause</th><th>Affected resources</th></tr></thead><tbody>{% for incident in incidents %}<tr><td class="finding-id">{{ incident.id }}</td><td><span class="badge {{ incident.severity }}">{{ incident.severity }}</span></td><td><span class="badge {{ incident.temporal_status }}">{{ incident.temporal_status }}</span></td><td>{{ incident.time_bucket }}</td><td><b>{{ incident.title }}</b><div class="detail">{{ incident.finding_count }} matching findings</div></td><td><b>{{ incident.resource_count }}</b><div class="incident-resources">{{ incident.resources|join('\n') }}</div></td></tr>{% else %}<tr><td colspan="6" class="empty">No correlated log incidents.</td></tr>{% endfor %}</tbody></table></div></section>
<section class="tab-panel" id="tab-events"><div class="section"><h2>Events timeline</h2><div class="controls"><input id="event-search" type="search" placeholder="Search event message or resource"><select id="event-severity"><option value="">All severities</option>{% for value in filter_options.severities %}<option>{{ value }}</option>{% endfor %}</select><input id="event-namespace" type="search" placeholder="Namespace"><input id="event-reason" type="search" placeholder="Reason"></div><div class="result-count"><span id="event-visible-count">{{ events|length }}</span> of {{ events|length }} events</div><div class="table-scroll"><table class="events-table"><thead><tr><th>Time</th><th>Severity</th><th>Namespace</th><th>Reason</th><th>Message</th></tr></thead><tbody id="event-rows">{% for e in events %}<tr data-severity="{{ e.severity }}" data-namespace="{{ e.namespace or '-' }}" data-reason="{{ e.reason or '-' }}" data-search="{{ (e.timestamp ~ ' ' ~ (e.namespace or '') ~ ' ' ~ (e.reason or '') ~ ' ' ~ (e.message or ''))|lower|e }}"><td>{{ e.timestamp }}</td><td><span class="badge {{ e.severity }}">{{ e.severity }}</span></td><td>{{ e.namespace or '-' }}</td><td>{{ e.reason or '-' }}</td><td>{{ e.message or '' }}</td></tr>{% else %}<tr><td colspan="5" class="empty">No events captured.</td></tr>{% endfor %}</tbody></table></div></div></section>
<section class="tab-panel" id="tab-inventory"><div class="section"><h2>Observed resource inventory</h2><table><thead><tr><th>Kind</th><th>Count</th></tr></thead><tbody>{% for kind,count in observation_counts.items() %}<tr><td>{{ kind }}</td><td>{{ count }}</td></tr>{% else %}<tr><td colspan="2" class="empty">No observations captured.</td></tr>{% endfor %}</tbody></table></div></section>
<section class="tab-panel" id="tab-history"><div class="section"><h2>Resource lifecycle history</h2><p>{{ resource_history|length }} changed states and tombstones retained according to the configured retention policy.</p><div class="table-scroll"><table><thead><tr><th>Observed</th><th>Event</th><th>Kind</th><th>Namespace</th><th>Name</th><th>Status</th></tr></thead><tbody>{% for item in resource_history %}<tr><td>{{ item.observed_at }}</td><td>{{ item.event_type }}</td><td>{{ item.kind }}</td><td>{{ item.namespace or '-' }}</td><td class="resource">{{ item.name or '-' }}</td><td>{{ item.status or '-' }}</td></tr>{% else %}<tr><td colspan="6" class="empty">No resource history captured.</td></tr>{% endfor %}</tbody></table></div></div></section>
<section class="tab-panel" id="tab-pods"><div class="section"><h2>Pod inventory</h2><p>{{ pod_inventory|length }} current Pods. Node and Pod IP are hidden when report anonymization is enabled.</p><div class="controls"><input id="pod-search" type="search" placeholder="Search Pod, node or QoS"><input id="pod-namespace" type="search" placeholder="Namespace"><input id="pod-status" type="search" placeholder="Status"><input id="pod-node" type="search" placeholder="Node"></div><div class="result-count"><span id="pod-visible-count">{{ pod_inventory|length }}</span> of {{ pod_inventory|length }} Pods</div><div class="table-scroll"><table><thead><tr><th>Namespace</th><th>Pod</th><th>Status</th><th>Ready</th><th>Restarts</th><th>Node</th><th>Nominated node</th><th>Pod IP</th><th>Readiness gates</th><th>QoS</th><th>CPU usage / limit</th><th>Memory usage / limit</th><th>Disk limit</th><th>Disk usage</th><th>Observed</th></tr></thead><tbody id="pod-rows">{% for pod in pod_inventory %}<tr data-namespace="{{ pod.namespace }}" data-status="{{ pod.status }}" data-node="{{ pod.node }}" data-search="{{ (pod.namespace ~ ' ' ~ pod.name ~ ' ' ~ pod.status ~ ' ' ~ pod.node ~ ' ' ~ pod.nominated_node ~ ' ' ~ pod.qos)|lower|e }}"><td>{{ pod.namespace }}</td><td class="resource">{{ pod.name }}</td><td>{{ pod.status }}</td><td>{{ pod.ready }}</td><td>{{ pod.restarts }}</td><td>{{ pod.node }}</td><td>{{ pod.nominated_node }}</td><td>{{ pod.pod_ip }}</td><td>{{ pod.readiness_gates }}</td><td>{{ pod.qos }}</td><td>{{ pod.cpu_usage }} / {{ pod.cpu_limit }}{% if pod.cpu_limit_pct is not none %} ({{ pod.cpu_limit_pct }}%){% endif %}</td><td>{{ pod.memory_usage }} / {{ pod.memory_limit }}{% if pod.memory_limit_pct is not none %} ({{ pod.memory_limit_pct }}%){% endif %}</td><td>{{ pod.ephemeral_storage_limit }}</td><td>{{ pod.disk_usage }}</td><td>{{ pod.observed }}</td></tr>{% else %}<tr><td colspan="15" class="empty">No current Pod inventory captured.</td></tr>{% endfor %}</tbody></table></div></div><div class="section"><h2>Pod lifecycle history</h2><p>{{ pod_history|length }} recorded Pod observations and lifecycle events retained by the database.</p><div class="controls"><input id="pod-history-search" type="search" placeholder="Search historical Pod or namespace"><input id="pod-history-event" type="search" placeholder="Event type"></div><div class="result-count"><span id="pod-history-visible-count">{{ pod_history|length }}</span> of {{ pod_history|length }} historical entries</div><div class="table-scroll"><table><thead><tr><th>Time</th><th>Event</th><th>Namespace</th><th>Pod</th><th>Status</th></tr></thead><tbody id="pod-history-rows">{% for pod in pod_history %}<tr data-event="{{ pod.event_type }}" data-search="{{ (pod.timestamp ~ ' ' ~ (pod.event_type or '') ~ ' ' ~ (pod.namespace or '') ~ ' ' ~ (pod.name or '') ~ ' ' ~ (pod.status or ''))|lower|e }}"><td>{{ pod.timestamp }}</td><td>{{ pod.event_type }}</td><td>{{ pod.namespace or '-' }}</td><td class="resource">{{ pod.name }}</td><td>{{ pod.status or '-' }}</td></tr>{% else %}<tr><td colspan="5" class="empty">No Pod lifecycle history captured.</td></tr>{% endfor %}</tbody></table></div></div></section>
<section class="tab-panel" id="tab-methodology"><div class="section"><h2>Methodology and interpretation</h2><ul class="method-list"><li><b>Current</b>: confirmed now or observed within the last 24 hours.</li><li><b>Review</b>: cumulative signal without a reliable occurrence timestamp.</li><li><b>Historical</b>: last supporting restart or log evidence is older than 24 hours.</li><li>Pod-level findings are aggregated at their owning workload (Deployment, ReplicaSet, StatefulSet, DaemonSet, Job or ReplicationController).</li><li>Different active finding or effective configuration profiles among sibling pods produce workload-level peer-drift findings.</li><li>Severity counts include Current findings only.</li><li>Configuration findings remain Current until a complete snapshot no longer confirms them.</li><li>Log incidents correlate the primary signature and one-hour time window.</li><li>Reports are generated read-only from SQLite observations.</li><li>Secret values remain redacted; output anonymization follows report settings.</li></ul></div><div class="section"><h2>Audit coverage</h2><table><thead><tr><th>Resource</th><th>Status</th><th>Objects</th><th>Rules</th></tr></thead><tbody>{% for kind,item in audit_coverage.items() %}<tr><td>{{ kind }}</td><td>{{ item.status }}</td><td>{{ item.objects or 0 }}</td><td>{{ "yes" if item.rules else "inventory only" }}</td></tr>{% else %}<tr><td colspan="4" class="empty">No completed snapshot coverage data.</td></tr>{% endfor %}</tbody></table><h3>Not checked by API-only mode</h3><ul>{% for item in not_checked %}<li>{{ item }}</li>{% else %}<li>No limitations recorded.</li>{% endfor %}</ul></div></section>
</main>
<script>
const buttons=[...document.querySelectorAll('.tab-button')];const panels=[...document.querySelectorAll('.tab-panel')];buttons.forEach(button=>button.addEventListener('click',()=>{buttons.forEach(item=>item.classList.toggle('active',item===button));panels.forEach(panel=>panel.classList.toggle('active',panel.id==='tab-'+button.dataset.tab));history.replaceState(null,'','#'+button.dataset.tab)}));
const initial=location.hash.slice(1);if(initial){const target=buttons.find(button=>button.dataset.tab===initial);if(target)target.click()}
const PAGE_SIZE=50;function paginateTable(table,page=1){const rows=[...table.tBodies[0]?.rows||[]];const visibleRows=rows.filter(row=>!row.classList.contains('hidden'));const pages=Math.ceil(visibleRows.length/PAGE_SIZE);rows.forEach(row=>row.classList.remove('pagination-hidden'));const old=table.nextElementSibling;if(old?.classList.contains('table-pagination'))old.remove();if(pages<=1)return;page=Math.max(1,Math.min(page,pages));visibleRows.forEach((row,index)=>row.classList.toggle('pagination-hidden',Math.floor(index/PAGE_SIZE)+1!==page));const controls=document.createElement('nav');controls.className='table-pagination';controls.setAttribute('aria-label','Table pages');controls.innerHTML=`<span>${visibleRows.length} records · page ${page} of ${pages}</span>`;for(let number=1;number<=pages;number++){const button=document.createElement('button');button.type='button';button.textContent=number;button.classList.toggle('active',number===page);button.addEventListener('click',()=>paginateTable(table,number));controls.append(button)}table.insertAdjacentElement('afterend',controls)}const paginatedTables=[...document.querySelectorAll('main table')];paginatedTables.forEach(table=>paginateTable(table));const controls=['finding-search','finding-severity','finding-status','finding-category','finding-namespace'].map(id=>document.getElementById(id));const rows=[...document.querySelectorAll('#finding-rows tr')];function filterFindings(){const query=controls[0].value.trim().toLowerCase();let visible=0;rows.forEach(row=>{const show=(!query||row.dataset.search.includes(query))&&(!controls[1].value||row.dataset.severity===controls[1].value)&&(!controls[2].value||row.dataset.status===controls[2].value)&&(!controls[3].value||row.dataset.category===controls[3].value)&&(!controls[4].value||row.dataset.namespace===controls[4].value);row.classList.toggle('hidden',!show);if(show)visible++});document.getElementById('finding-visible-count').textContent=visible;const findingsTable=document.querySelector('#finding-rows')?.closest('table');if(findingsTable)paginateTable(findingsTable)}controls.forEach(control=>control.addEventListener('input',filterFindings));
function bindReportFilter(rowSelector,countId,controlIds,matcher){const filterRows=[...document.querySelectorAll(rowSelector)];const filterControls=controlIds.map(id=>document.getElementById(id));function apply(){let visible=0;filterRows.forEach(row=>{const show=matcher(row,filterControls);row.classList.toggle('hidden',!show);if(show)visible++});document.getElementById(countId).textContent=visible;const table=document.querySelector(rowSelector)?.closest('table');if(table)paginateTable(table)}filterControls.forEach(control=>control.addEventListener('input',apply))}bindReportFilter('#event-rows tr[data-search]','event-visible-count',['event-search','event-severity','event-namespace','event-reason'],(row,filters)=>{const [search,severity,namespace,reason]=filters.map(item=>item.value.trim().toLowerCase());return(!search||row.dataset.search.includes(search))&&(!severity||row.dataset.severity.toLowerCase()===severity)&&(!namespace||row.dataset.namespace.toLowerCase().includes(namespace))&&(!reason||row.dataset.reason.toLowerCase().includes(reason))});bindReportFilter('#pod-rows tr[data-search]','pod-visible-count',['pod-search','pod-namespace','pod-status','pod-node'],(row,filters)=>{const [search,namespace,status,node]=filters.map(item=>item.value.trim().toLowerCase());return(!search||row.dataset.search.includes(search))&&(!namespace||row.dataset.namespace.toLowerCase().includes(namespace))&&(!status||row.dataset.status.toLowerCase().includes(status))&&(!node||row.dataset.node.toLowerCase().includes(node))});bindReportFilter('#pod-history-rows tr[data-search]','pod-history-visible-count',['pod-history-search','pod-history-event'],(row,filters)=>{const [search,event]=filters.map(item=>item.value.trim().toLowerCase());return(!search||row.dataset.search.includes(search))&&(!event||row.dataset.event.toLowerCase().includes(event))});
</script></body></html>"""


def _sections(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    categories = _counts(findings, "category")
    return [
        {"title": category.replace("-", " ").title(), "findings": [item for item in findings if (item.get("category") or "unknown") == category]}
        for category in categories
    ]


def _html_to_pdf_text(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _evidence(value: Any) -> Any:
    if isinstance(value, str):
        return loads(value, value)
    return value


def _markdown_text(value: Any) -> str:
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _counts(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for item in items:
        label = str(item.get(key) or "unknown")
        result[label] = result.get(label, 0) + 1
    return dict(sorted(result.items(), key=lambda pair: (-pair[1], pair[0])))


def _pod_inventory_rows(raw_items: list[dict[str, Any]], display_items: list[dict[str, Any]], anonymized: bool, salt: str = "") -> list[dict[str, Any]]:
    """Expose the safe Pod inventory fields in human-readable reports."""
    rows = []
    for raw_item, display_item in zip(raw_items, display_items):
        inventory = ((raw_item.get("raw") or {}).get("auditPodInventory") or {})
        rows.append(
            {
                "namespace": display_item.get("namespace") or "-",
                "name": display_item.get("name") or "-",
                "event_type": raw_item.get("event_type") or "CURRENT",
                "ready": inventory.get("ready") or "-",
                "status": inventory.get("status") or "-",
                "restarts": inventory.get("restarts", 0),
                "node": scrub_text(inventory.get("node") or "-", salt) if anonymized else inventory.get("node") or "-",
                "nominated_node": scrub_text(inventory.get("nominated_node") or "-", salt) if anonymized else inventory.get("nominated_node") or "-",
                "pod_ip": anonymize_ip(inventory.get("pod_ip") or "-", salt) if anonymized else inventory.get("pod_ip") or "-",
                "readiness_gates": inventory.get("readiness_gates") or "-",
                "qos": inventory.get("qos") or "-",
                "cpu_usage": inventory.get("cpu_usage") or "-",
                "cpu_limit": inventory.get("cpu_limit") or "-",
                "cpu_limit_pct": inventory.get("cpu_limit_pct"),
                "memory_usage": inventory.get("memory_usage") or "-",
                "memory_limit": inventory.get("memory_limit") or "-",
                "memory_limit_pct": inventory.get("memory_limit_pct"),
                "ephemeral_storage_limit": inventory.get("ephemeral_storage_limit") or "-",
                "disk_usage": inventory.get("disk_usage") or "unavailable",
                "observed": display_item.get("timestamp"),
            }
        )
    return rows


def _bar_items(counts: dict[str, int], labels: list[str] | None = None, limit: int = 8) -> list[dict[str, Any]]:
    pairs = [(label, int(counts.get(label, 0))) for label in labels] if labels else list(counts.items())[:limit]
    maximum = max([count for _, count in pairs] or [1]) or 1
    return [{"label": label, "count": count, "width": max(2, round((count / maximum) * 100)) if count else 0} for label, count in pairs]


def _severity_chart(counts: dict[str, int]) -> Drawing:
    labels = ["Critical", "High", "Medium", "Low", "Info"]
    values = [int(counts.get(label, 0)) for label in labels]
    drawing = Drawing(180, 120)
    pie = Pie()
    pie.x = 25
    pie.y = 12
    pie.width = 95
    pie.height = 95
    pie.data = values
    pie.labels = [f"{label} {value}" if value else "" for label, value in zip(labels, values)]
    pie.slices.strokeWidth = 0.5
    pie.slices[0].fillColor = colors.HexColor("#991b1b")
    pie.slices[1].fillColor = colors.HexColor("#b45309")
    pie.slices[2].fillColor = colors.HexColor("#92400e")
    pie.slices[3].fillColor = colors.HexColor("#0369a1")
    pie.slices[4].fillColor = colors.HexColor("#64748b")
    drawing.add(String(4, 108, "Findings by severity", fontSize=8, fillColor=colors.HexColor("#172033")))
    drawing.add(pie)
    return drawing


def _category_chart(counts: dict[str, int]) -> Drawing:
    top = list(counts.items())[:8]
    drawing = Drawing(360, 145)
    chart = VerticalBarChart()
    chart.x = 30
    chart.y = 30
    chart.height = 85
    chart.width = 300
    chart.data = [[value for _, value in top] or [0]]
    chart.categoryAxis.categoryNames = [label[:16] for label, _ in top] or ["none"]
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max([value for _, value in top] or [1])
    chart.valueAxis.valueStep = max(1, chart.valueAxis.valueMax // 5 or 1)
    chart.bars[0].fillColor = colors.HexColor("#2563eb")
    chart.categoryAxis.labels.angle = 30
    chart.categoryAxis.labels.fontSize = 6
    chart.valueAxis.labels.fontSize = 6
    drawing.add(String(4, 128, "Top finding categories", fontSize=8, fillColor=colors.HexColor("#172033")))
    drawing.add(chart)
    return drawing


def _write_pdf_reportlab(path: str, payload: dict[str, Any]) -> None:
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("AuditTitle", parent=styles["Title"], fontSize=23, leading=28, textColor=colors.white, spaceAfter=8)
    cover_body = ParagraphStyle("AuditCover", parent=styles["BodyText"], fontSize=9, leading=12, textColor=colors.HexColor("#dbe4ef"))
    h2 = ParagraphStyle("AuditH2", parent=styles["Heading2"], fontSize=13, leading=16, textColor=colors.HexColor("#172033"), spaceBefore=12, spaceAfter=6)
    body = ParagraphStyle("AuditBody", parent=styles["BodyText"], fontSize=8.5, leading=11, textColor=colors.HexColor("#1f2937"))
    small = ParagraphStyle("AuditSmall", parent=body, fontSize=7.5, leading=9)
    tiny = ParagraphStyle("AuditTiny", parent=body, fontSize=6.5, leading=8)
    cover = Table(
        [[Paragraph("Neto Kube Auditor", title)], [Paragraph(f"Kubernetes / OpenShift technical audit report<br/>Cluster: <b>{_html_to_pdf_text(payload['cluster_name'])}</b><br/>Generated at {_html_to_pdf_text(payload['generated_at'])}", cover_body)]],
        colWidths=[170 * mm],
    )
    cover.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#101827")), ("BOX", (0, 0), (-1, -1), 0, colors.HexColor("#101827")), ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, 0), 16), ("BOTTOMPADDING", (0, 1), (-1, 1), 16)]))
    story: list[Any] = [cover, Spacer(1, 10)]
    summary_rows = [["Current", "Problem pods", "Critical", "High", "Review", "Historical"],
                    [payload["summary"]["current_findings"], payload["summary"]["problematic_pods"],
                     payload["summary"]["findings_by_severity"].get("Critical", 0), payload["summary"]["findings_by_severity"].get("High", 0),
                     payload["summary"]["review_findings"], payload["summary"]["historical_findings"]]]
    table = Table(summary_rows, repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7")), ("BACKGROUND", (0, 1), (-1, 1), colors.white), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#cbd5e1")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("FONTSIZE", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.extend(
        [
            table,
            Spacer(1, 8),
            _severity_chart(payload["summary"]["findings_by_severity"]),
            Spacer(1, 6),
            _category_chart(payload["finding_counts_by_category"]),
            Spacer(1, 8),
            Paragraph("1. Executive summary", h2),
            Paragraph(_html_to_pdf_text(payload["executive_summary"]), body),
        ]
    )
    for idx, section in enumerate(payload["sections"], start=2):
        story.append(Paragraph(f"{idx}. {_html_to_pdf_text(section['title'])}", h2))
        if not section["findings"]:
            story.append(Paragraph("No active findings in this section.", body))
            continue
        rows = [["Severity", "Resource", "Title", "Evidence and recommendation"]]
        for f in section["findings"]:
            resource = f"{f.get('resource_kind') or ''}/{f.get('namespace') or '-'}/{f.get('resource_name') or '-'}"
            evidence = dumps(_evidence(f.get("evidence"))) if f.get("evidence") not in (None, "", {}) else ""
            detail = f"{f.get('description') or ''}\nRecommendation: {f.get('recommendation') or ''}"
            if f.get("pod_scope"):
                detail = f"{f['pod_scope']}\n{detail}"
            if evidence:
                detail += f"\nEvidence: {evidence[:1200]}"
            rows.append(
                [
                    Paragraph(_html_to_pdf_text(f"{f['severity']} / {f.get('temporal_status', 'Current')}"), small),
                    Paragraph(_html_to_pdf_text(resource), small),
                    Paragraph(_html_to_pdf_text(f["title"]), small),
                    Paragraph(_html_to_pdf_text(detail), tiny),
                ]
            )
        tbl = Table(rows, colWidths=[22 * mm, 42 * mm, 48 * mm, 58 * mm], repeatRows=1)
        tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7")), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#d8dee8")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 7)]))
        story.append(tbl)
    story.append(PageBreak())
    story.append(Paragraph("13. Events timeline", h2))
    event_rows = [["Time", "Severity", "Namespace", "Reason", "Message"]]
    for e in payload["events"]:
        event_rows.append([Paragraph(_html_to_pdf_text(e.get("timestamp")), tiny), Paragraph(_html_to_pdf_text(e.get("severity")), tiny), Paragraph(_html_to_pdf_text(e.get("namespace") or ""), tiny), Paragraph(_html_to_pdf_text(e.get("reason") or ""), tiny), Paragraph(_html_to_pdf_text(e.get("message") or ""), tiny)])
    event_table = Table(event_rows, colWidths=[38 * mm, 20 * mm, 32 * mm, 28 * mm, 52 * mm], repeatRows=1)
    event_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7")), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#d8dee8")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(event_table)
    story.append(Paragraph("14. Observed resources", h2))
    observation_rows = [["Kind", "Count"]]
    for kind, count in payload["observation_counts"].items():
        observation_rows.append([Paragraph(_html_to_pdf_text(kind), small), count])
    observation_table = Table(observation_rows, colWidths=[90 * mm, 25 * mm], repeatRows=1)
    observation_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7")), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#d8dee8"))]))
    story.extend([observation_table, Paragraph("15. Pod inventory", h2)])
    pod_rows = [["Namespace", "Pod", "Status", "Ready", "Restarts", "Node", "CPU usage / limit", "Memory usage / limit"]]
    for pod in payload["pod_inventory"]:
        cpu = f"{pod['cpu_usage']} / {pod['cpu_limit']}" + (f" ({pod['cpu_limit_pct']}%)" if pod["cpu_limit_pct"] is not None else "")
        memory = f"{pod['memory_usage']} / {pod['memory_limit']}" + (f" ({pod['memory_limit_pct']}%)" if pod["memory_limit_pct"] is not None else "")
        pod_rows.append([Paragraph(_html_to_pdf_text(pod[key]), tiny) for key in ("namespace", "name", "status", "ready", "restarts", "node")] + [Paragraph(_html_to_pdf_text(cpu), tiny), Paragraph(_html_to_pdf_text(memory), tiny)])
    if len(pod_rows) == 1:
        pod_rows.append([Paragraph("No current Pod inventory captured.", small)] + [""] * 7)
    pod_table = Table(pod_rows, colWidths=[20 * mm, 31 * mm, 20 * mm, 13 * mm, 13 * mm, 24 * mm, 25 * mm, 25 * mm], repeatRows=1)
    pod_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7")), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#d8dee8")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.extend([pod_table, Paragraph("16. Recommendations", h2), Paragraph("Fix Critical and High findings first. Then address namespace policies, resource management defaults, route TLS and recurring operator issues.", body), Paragraph("17. Appendix: evidence references", h2), Paragraph("Findings, events and observed resources are exported with redaction/anonymization applied according to the current settings.", body)])
    doc.build(story)


def _write_pdf(path: str, payload: dict[str, Any]) -> None:
    html = _render_html(payload)
    try:
        from weasyprint import HTML
    except Exception:
        _write_pdf_reportlab(path, payload)
        return
    HTML(string=html, base_url=os.getcwd()).write_pdf(path)


def _render_html(payload: dict[str, Any]) -> str:
    environment = Environment(
        autoescape=select_autoescape(default_for_string=True, default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return environment.from_string(HTML_TEMPLATE).render(**payload)


_JSON_REPORT_EXCLUDED_FIELDS = {"raw", "raw_json", "raw_obj", "evidence", "evidence_json", "summary_json"}


def _json_report_value(value: Any) -> Any:
    """Remove storage internals; JSON reports mirror the human report evidence."""
    if isinstance(value, dict):
        return {
            key: _json_report_value(item)
            for key, item in value.items()
            if key not in _JSON_REPORT_EXCLUDED_FIELDS
        }
    if isinstance(value, list):
        return [_json_report_value(item) for item in value]
    return value


def _json_report_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the useful report content without full Kubernetes manifests."""
    return _json_report_value(
        {
            "generated_at": payload["generated_at"],
            "cluster_name": payload["cluster_name"],
            "anonymized": payload["anonymized"],
            "executive_summary": payload["executive_summary"],
            "summary": payload["summary"],
            "severity_chart_items": payload["severity_chart_items"],
            "category_chart_items": payload["category_chart_items"],
            "finding_counts_by_category": payload["finding_counts_by_category"],
            "findings": payload["findings"],
            "incidents": payload["incidents"],
            "events": payload["events"],
            "observation_counts": payload["observation_counts"],
            "pod_inventory": payload["pod_inventory"],
            "pod_history": payload["pod_history"],
            "audit_coverage": payload["audit_coverage"],
            "not_checked": payload["not_checked"],
        }
    )


def generate_report(repo: AuditRepository, fmt: str, output: str, cluster_name: str, anonymize: bool = True, anonymization_salt: str = "ocp-audit-agent") -> dict[str, Any]:
    fmt = fmt.lower()
    Path(os.path.dirname(output) or ".").mkdir(parents=True, exist_ok=True)
    findings = repo.list_findings(limit=10000)
    events = repo.list_events(limit=10000)
    observations = repo.list_observations(limit=50000)
    raw_pods = [item for item in observations if item.get("kind") == "Pod"]
    pod_history = repo.list_pod_history(limit=50000, include_raw=False)
    observation_counts = repo.observation_counts_by_kind()
    repository_summary = repo.summary()
    snapshot_summary = repo.latest_snapshot_summary()
    display_cluster_name = cluster_name
    display_pods = raw_pods
    findings = prepare_findings(findings, observations=observations)
    if anonymize:
        terms = load_terms()
        findings = anonymize_findings(findings, anonymization_salt, terms)
        events = anonymize_events(events, anonymization_salt, terms)
        pod_history = anonymize_observations(pod_history, anonymization_salt, terms)
        display_pods = [
            {"namespace": scrub_text(item.get("namespace"), anonymization_salt, terms), "name": scrub_text(item.get("name"), anonymization_salt, terms), "timestamp": item.get("timestamp")}
            for item in raw_pods
        ]
        display_cluster_name = "cluster-" + __import__("hashlib").sha256(f"{anonymization_salt}:cluster:{cluster_name}".encode()).hexdigest()[:10]
    view = build_audit_view(findings, repository_summary["events_last_hour"])
    summary = view["summary"]
    current_critical_high = [item for item in view["current_findings"] if item.get("severity") in {"Critical", "High"}]
    executive_summary = (
        f"The current audit contains {summary['current_findings']} confirmed findings affecting {summary['problematic_pods']} problematic pods. "
        f"There are {summary['findings_by_severity'].get('Critical', 0)} Critical and {summary['findings_by_severity'].get('High', 0)} High findings requiring priority review. "
        f"Another {summary['review_findings']} cumulative signals require validation, while {summary['historical_findings']} findings are retained as historical context and excluded from current severity totals."
    )
    namespaces = sorted({str(item.get("namespace") or "-") for item in view["findings"]})
    categories = sorted({str(item.get("category") or "unknown") for item in view["findings"]})
    payload = {
        "generated_at": iso_now(),
        "cluster_name": display_cluster_name,
        "anonymized": anonymize,
        "summary": summary,
        "findings": view["findings"],
        "events": events,
        "pod_inventory": _pod_inventory_rows(raw_pods, display_pods, anonymize, anonymization_salt),
        "pod_history": pod_history,
        "observation_counts": observation_counts,
        "finding_counts_by_category": view["finding_counts_by_category"],
        "sections": _sections(view["findings"]),
        "incidents": view["incidents"],
        "priority_findings": current_critical_high[:20],
        "executive_summary": executive_summary,
        "filter_options": {"severities": SEVERITIES, "categories": categories, "namespaces": namespaces},
        "audit_coverage": snapshot_summary.get("coverage") or {},
        "not_checked": snapshot_summary.get("not_checked") or [],
    }
    payload["severity_chart_items"] = _bar_items(summary["findings_by_severity"], ["Critical", "High", "Medium", "Low", "Info"])
    payload["category_chart_items"] = _bar_items(payload["finding_counts_by_category"], limit=8)
    if fmt == "json":
        content = dumps(_json_report_payload(payload))
    elif fmt == "markdown":
        lines = [f"# Neto Kube Auditor Report", "", f"Generated at: {payload['generated_at']}", "", "## Executive summary", executive_summary]
        lines.append(f"- Events in last hour: {summary['events_last_hour']}")
        lines.append(f"- Problematic pods: {summary['problematic_pods']}")
        lines.extend(["", "## Audit coverage"])
        for kind, item in payload["audit_coverage"].items():
            lines.append(f"- `{kind}`: {item.get('status')} ({item.get('objects', 0)} objects; rules={item.get('rules', False)})")
        lines.extend(["", "### Not checked by API-only mode"])
        lines.extend(f"- {item}" for item in payload["not_checked"])
        for section in payload["sections"]:
            lines.extend(["", f"## {section['title']}"])
            if not section["findings"]:
                lines.append("No active findings.")
            for f in section["findings"]:
                evidence = f" Evidence: `{_markdown_text(dumps(f.get('evidence_obj')))}`" if f.get("evidence_obj") else ""
                lines.append(f"- **{f['severity']} / {f['temporal_status']}** `{_markdown_text(f['resource'])}`: {_markdown_text(f['title'])} - {_markdown_text(f.get('recommendation'))}{evidence}")
        lines.extend(["", "## Events timeline"])
        for e in events:
            lines.append(f"- {e['timestamp']} **{e['severity']}** {_markdown_text(e.get('namespace') or '-')} {_markdown_text(e.get('reason') or '-')}: {_markdown_text(e.get('message'))}")
        lines.extend(["", "## Observed resources"])
        for kind, count in observation_counts.items():
            lines.append(f"- {kind}: {count}")
        lines.extend(["", "## Pod inventory", "", "| Namespace | Pod | Status | Ready | Restarts | Node | Nominated node | Pod IP | Readiness gates | QoS | CPU usage / limit | Memory usage / limit | Disk limit | Disk usage |", "| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- |"])
        for pod in payload["pod_inventory"]:
            cpu = f"{pod['cpu_usage']} / {pod['cpu_limit']}" + (f" ({pod['cpu_limit_pct']}%)" if pod["cpu_limit_pct"] is not None else "")
            memory = f"{pod['memory_usage']} / {pod['memory_limit']}" + (f" ({pod['memory_limit_pct']}%)" if pod["memory_limit_pct"] is not None else "")
            lines.append(f"| {pod['namespace']} | {pod['name']} | {pod['status']} | {pod['ready']} | {pod['restarts']} | {pod['node']} | {pod['nominated_node']} | {pod['pod_ip']} | {pod['readiness_gates']} | {pod['qos']} | {cpu} | {memory} | {pod['ephemeral_storage_limit']} | {pod['disk_usage']} |")
        if not payload["pod_inventory"]:
            lines.append("| - | No current Pod inventory captured. | - | - | - | - | - | - | - | - | - | - | - | - |")
        lines.extend(["", "## Pod lifecycle history"])
        for pod in payload["pod_history"]:
            lines.append(f"- {pod.get('timestamp')} **{pod.get('event_type')}** `{pod.get('namespace') or '-'}/{pod.get('name') or '-'}`: {pod.get('status') or '-'}")
        content = "\n".join(lines) + "\n"
    elif fmt == "html":
        content = _render_html(payload)
    elif fmt == "pdf":
        _write_pdf(output, payload)
        report_id = repo.add_report(fmt, output, {**summary, "anonymized": anonymize})
        return {"id": report_id, "path": output, "format": fmt, "summary": summary}
    else:
        raise ValueError("format must be html, markdown, json or pdf")
    Path(output).write_text(content, encoding="utf-8")
    report_id = repo.add_report(fmt, output, {**summary, "anonymized": anonymize})
    return {"id": report_id, "path": output, "format": fmt, "summary": summary}
