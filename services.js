'use strict';
// Associations describe candidates, not packet-level rule applicability.
const ServiceAssessment = (() => {
  const baseline = 'Unverified — no matching baseline';
  function executable(value, windowsDirectory='C:\\Windows') {
    let path = String(value || '').trim().replace(/%SystemRoot%|%windir%/gi,windowsDirectory);
    if (path.startsWith('"')) path = path.slice(1).split('"')[0];
    else { const end = path.match(/\.exe(?=\s|$)/i); if (end) path=path.slice(0,end.index+4); }
    return path.replace(/\//g,'\\').toLowerCase();
  }
  function origin(path, windowsDirectory) {
    const p=executable(path,windowsDirectory), root=executable(windowsDirectory,windowsDirectory).replace(/\\$/,'');
    if(!p || ['any','system'].includes(p) || p.includes('%')) return 'Unresolved association';
    return p.startsWith(root+'\\') ? 'Windows-directory path association; publisher and default status unverified' : 'Application-path association; publisher and default status unverified';
  }
  function ruleOrigin(rule, data) {
    const matches=(data.ServiceInventory||[]).filter(s=>s.Name.toLowerCase()===String(rule.Service).toLowerCase());
    if(matches.length) return `Service association: ${matches[0].Name}. ${origin(matches[0].Path,data.WindowsDirectory)}`;
    if(rule.Package && rule.Package!=='Any') return 'Package-associated; package publisher and default status unverified';
    return origin(rule.Application,data.WindowsDirectory);
  }
  function analyze(data) {
    const services=data.ServiceInventory||[], rules=data.Rules||[], endpoints=data.Listeners||[];
    const byPID=new Map();for(const s of services){if(s.PID>0){if(!byPID.has(s.PID))byPID.set(s.PID,[]);byPID.get(s.PID).push(s.Name);}}
    return services.map(s=>{
      const path=executable(s.Path,data.WindowsDirectory);
      const direct=rules.filter(r=>String(r.Service).toLowerCase()===s.Name.toLowerCase());
      const app=rules.filter(r=>(!r.Service||r.Service==='Any') && r.Application && !['Any','System'].includes(r.Application) && path && executable(r.Application,data.WindowsDirectory)===path);
      const inbound=[...direct,...app].filter(r=>r.Enabled&&r.Direction==='Inbound'&&r.Action==='Allow');
      const ports=s.PID>0?endpoints.filter(p=>p.PID===s.PID):[];
      const siblings=byPID.get(s.PID)||[];
      const dependentServices=(s.Dependents||[]).map(name=>services.find(v=>v.Name.toLowerCase()===String(name).toLowerCase())).filter(Boolean);
      const runningDependents=dependentServices.filter(v=>v.State==='Running').map(v=>v.Name);
      const need=s.DependenciesAvailable ? (runningDependents.length?`Running dependents: ${runningDependents.join(', ')}. Necessity unresolved.`:'No running dependents observed. Necessity unresolved.') : 'Dependency information unavailable. Necessity unresolved.';
      return {service:s,path,direct,app,inbound,ports,siblings,shared:siblings.length>1,priority:s.State==='Running'||s.Startup==='Auto'||inbound.length>0,need,origin:origin(s.Path,data.WindowsDirectory)};
    });
  }
  return {baseline,executable,origin,ruleOrigin,analyze};
})();
if(typeof module!=='undefined')module.exports=ServiceAssessment;

function renderServiceAssessment(data) {
  const rows=ServiceAssessment.analyze(data);
  const box=document.getElementById('service-summary');
  box.replaceChildren(card('Installed services',String(rows.length),'Includes stopped and disabled services'),card('Running',String(rows.filter(r=>r.service.State==='Running').length),'State at collection time'),card('Inbound associations',String(rows.filter(r=>r.inbound.length).length),'Services with candidate inbound rules'),card('Shared-host endpoints',String(rows.filter(r=>r.shared&&r.ports.length).length),'Service ownership remains ambiguous'));
  function show(row){
    const d=document.getElementById('detail'),fields=document.getElementById('detail-fields');
    d.querySelector('h2').textContent='Service assessment';fields.replaceChildren();
    const values={...row.service,Executable:row.path,OriginAssessment:row.origin,DefaultRuleStatus:ServiceAssessment.baseline,WindowsNeed:row.need,UserNeed:'User requirement not established',SharedProcessServices:row.siblings,EndpointAssociation:row.shared?'Shared process: endpoints cannot be assigned to an individual service':'PID association only; not proof of rule usage'};
    for(const [k,v]of Object.entries(values))fields.append(el('dt',k),el('dd',str(v)));
    for(const [title,rules]of [['Service-specific rules',row.direct],['Executable candidate rules',row.app]]){fields.append(el('dt',title));const dd=el('dd');if(!rules.length)dd.append(el('span','No association found in collected data.'));for(const rule of rules){const b=el('button',`${rule.Name} · ${rule.Enabled?'Enabled':'Disabled'} · ${rule.Direction} ${rule.Action} · ${rule.Profile}`,'rule-link');b.onclick=()=>details(rule);dd.append(b,el('br'));}fields.append(dd);}
    fields.append(el('dt','Observed endpoints'));const endpoints=el('dd');endpoints.textContent=row.ports.map(p=>`${p.Protocol} ${p.Address}:${p.Port} (PID ${p.PID})`).join('\n')||'None observed; occasional or outbound-only use remains possible.';fields.append(endpoints);
    fields.append(el('dt','Interpretation'),el('dd','Service and executable associations do not establish that a rule permits an observed socket: protocol, port, profile, address, package, user, interface, and dynamic restrictions still apply. A service dependency is not a recommendation to disable or retain a service.'));
    d.showModal();
  }
  function filter(){
    const term=$('service-search').value.toLowerCase(), state=$('service-state').value,mode=$('service-priority').value;
    const selected=rows.filter(r=>(!state||r.service.State===state)&&(!term||JSON.stringify(r.service).toLowerCase().includes(term))&&(mode==='all'||mode==='priority'&&r.priority||mode==='inbound'&&r.inbound.length||mode==='shared'&&r.shared&&r.ports.length)).sort((a,b)=>Number(b.priority)-Number(a.priority)||b.inbound.length-a.inbound.length||a.service.Name.localeCompare(b.service.Name));
    $('service-count').textContent=data.ServiceInventory?`${selected.length} of ${rows.length} services · Select a service for dependencies, rules, and purpose.`:'Service inventory unavailable in this snapshot. Click Refresh settings; inspect collection issues if it remains unavailable.';
    const body=document.createDocumentFragment();
    for(const r of selected){const s=r.service,tr=el('tr'),name=el('td'),b=el('button',s.DisplayName||s.Name,'rule-link');b.onclick=()=>show(r);name.append(b,el('small',s.Name),el('small',s.Description||'Description unavailable'));tr.append(name);tr.append(el('td',`${s.State} / ${s.Startup}${s.DelayedAutoStart?' (delayed)':''}`),el('td',`${r.direct.length} service-specific · ${r.app.length} executable candidates · ${r.inbound.length} inbound allow`),el('td',`${r.ports.length} PID-associated${r.shared?' · shared host; ambiguous':''}`),el('td',`${r.need}\nYour need: not established`));body.append(tr);}
    if(!selected.length){const tr=el('tr'),td=el('td','No matching services.','empty');td.colSpan=5;tr.append(td);body.append(tr);}$('service-rows').replaceChildren(body);
  }
  for(const id of ['service-search','service-state','service-priority'])$(id).oninput=filter;
  filter();
  const associated=new Set(rows.flatMap(r=>[...r.direct,...r.app].map(rule=>rule.Id)));
  const gaps=data.Rules.filter(r=>r.Enabled&&r.Direction==='Inbound'&&r.Action==='Allow'&&!associated.has(r.Id));
  const section=el('article',undefined,'review-card');section.append(el('h2',`${gaps.length} inbound exceptions without a collected service association`),el('p','These may belong to desktop applications, packages, system networking, or unresolved paths. No service association is not evidence that a rule is unnecessary. Listener matching for desktop applications is outside this service assessment.'));
  const list=el('ul');for(const rule of gaps){const li=el('li'),b=el('button',rule.Name,'rule-link');b.onclick=()=>details(rule);li.append(b);list.append(li);}section.append(list);$('service-rule-gaps').replaceChildren(section);
}
