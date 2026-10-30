// Run with: node test_associations.js
const assert=require('node:assert/strict');
const a=require('./services.js');
const services=[
 {Name:'Alpha',Path:'%SystemRoot%\\System32\\svchost.exe -k shared',PID:42,State:'Running',Startup:'Auto',Dependents:['Beta'],DependenciesAvailable:true},
 {Name:'Beta',Path:'"C:\\Windows\\System32\\svchost.exe" -k shared',PID:42,State:'Running',Startup:'Manual',Dependents:[],DependenciesAvailable:true},
 {Name:'Idle',Path:'C:\\Vendor Tools\\worker.exe --service',PID:0,State:'Stopped',Startup:'Manual',Dependents:[],DependenciesAvailable:true}
];
const base={Enabled:true,Direction:'Inbound',Action:'Allow',Application:'C:\\Windows\\System32\\svchost.exe'};
const data={WindowsDirectory:'C:\\Windows',ServiceInventory:services,Rules:[
 {...base,Id:'direct',Service:'Alpha'},
 {...base,Id:'executable',Service:'Any'},
 {...base,Id:'other-service',Service:'Other'},
 {...base,Id:'idle',Service:'Idle',Application:'Any'}
],Listeners:[{PID:42,Port:135},{PID:0,Port:999}]};
const result=a.analyze(data);
assert.deepEqual(result[0].direct.map(r=>r.Id),['direct']);
assert.deepEqual(result[0].app.map(r=>r.Id),['executable']);
assert.deepEqual(result[1].direct,[]);
assert.equal(result[0].shared,true);
assert.equal(result[1].ports.length,1);
assert.equal(result[2].ports.length,0); // PID zero must not assign endpoints to stopped services.
assert.equal(result[2].priority,true); // A stopped service with inbound permission stays in priority review.
assert.match(result[0].need,/Beta/);
assert.equal(a.executable('C:\\Vendor Tools\\worker.exe --service'),'c:\\vendor tools\\worker.exe');
assert.match(a.origin('C:\\WindowsElsewhere\\service.exe',data.WindowsDirectory),/^Application-path/);
assert.match(a.ruleOrigin(data.Rules[0],data),/Service association: Alpha/);
assert.match(a.baseline,/Unverified/);
console.log('Association checks passed: specific service filters, executable candidates, shared hosts, stopped services, dependencies, and origin boundaries.');
