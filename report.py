"""Word reports from persisted scan evidence; never implies manual validation."""
import re
from docx import Document
from docx.shared import Inches, Pt, RGBColor

def safe(value):
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]', '', str(value))

def export(job, path):
    d = Document()
    for border in list(d.styles.element.xpath('.//w:pBdr')):
        border.getparent().remove(border)
    sec = d.sections[0]
    sec.top_margin = sec.bottom_margin = Inches(.75)
    d.styles['Normal'].font.name = 'Calibri'
    d.styles['Normal'].font.size = Pt(10)
    for name in ['Title','Heading 1','Heading 2']:
        d.styles[name].font.color.rgb = RGBColor(0,0,0)
    d.add_heading('Pentest Lab Scan Report',0)
    d.add_paragraph('Automated assessment of the configured target and exact host scope. Tool findings require manual validation before they are treated as confirmed vulnerabilities.')
    table=d.add_table(rows=0, cols=2); table.style='Light Shading Accent 1'
    for key,value in [('Version',job.get('version','Earlier version')),('Target',job.get('target','')),('Job',job['id']),('Status',job['status']),('Started',job['created']),('Finished',job.get('finished','In progress')),('Scope',', '.join(job.get('scope',[])))]:
        cells=table.add_row().cells; cells[0].text=key; cells[1].text=safe(value)
    d.add_heading('Coverage and limitations',1)
    d.add_paragraph('A skipped, failed, timed out or cancelled stage has not completed its checks. No findings does not establish that the target is secure. Archived URLs may be stale. Discovery and parameter results are observations, not vulnerability confirmations. Raw evidence is retained in the job folder.')
    d.add_paragraph('Configured limits: '+', '.join(f'{key} {value}' for key,value in job.get('limits',{}).items()))
    if job.get('discovery_counts'): d.add_paragraph('Discovery coverage: '+safe(job['discovery_counts']))
    if job.get('routing_limits'): d.add_paragraph('Routing coverage: '+safe(job['routing_limits']))
    if job.get('tools'):d.add_paragraph('Selected tools: '+', '.join(job['tools']))
    if job.get('disabled_tools'):d.add_paragraph('Tools not selected: '+', '.join(job['disabled_tools']))
    if job.get('passive_note'):d.add_paragraph(safe(job['passive_note']))
    for stage in job.get('stages',[]):
        d.add_paragraph(safe(stage['name']+' — '+stage['status']+': '+stage.get('detail','')))
    if job.get('coverage'):
        d.add_heading('Tool coverage',1)
        for name,item in job['coverage'].items():d.add_paragraph(safe(name+': '+item['state']+' '+item.get('detail','')))
    if job.get('summary'):d.add_paragraph('Result counts: '+safe(job['summary']))
    findings=job.get('findings',[])
    d.add_heading('Findings and observations',1)
    d.add_paragraph(f'{len(findings)} findings or observations were recorded.')
    for i,f in enumerate(findings,1):
        d.add_heading(safe(f"{i} {f['title']}"),2)
        for key in ['tool','kind','severity','url','evidence','recommendation']:
            d.add_paragraph(safe(key.capitalize()+': '+str(f.get(key,''))))
    d.save(path)
