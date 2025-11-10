#!/usr/bin/env node
/*
  Print a concise summary of SARIF findings to stdout.
  Usage:
    node scripts/print_sarif_summary.js .codeql-results/codeql-python.sarif
*/
const fs = require('fs');
const argv = process.argv.slice(2);
const sarifPath = argv[0] || '.codeql-results/codeql-python.sarif';
let fileFilter = null;
let ruleFilter = null;
for (let i = 1; i < argv.length; i++) {
  if (argv[i] === '--file' && argv[i+1]) { fileFilter = argv[i+1]; i++; continue; }
  if (argv[i] === '--rule' && argv[i+1]) { ruleFilter = argv[i+1]; i++; continue; }
}
function load(p){
  try { return JSON.parse(fs.readFileSync(p,'utf8')); }
  catch(e){ console.error('Failed to load SARIF:', e.message); process.exit(1); }
}
const data = load(sarifPath);
const findings = [];
for (const run of (data.runs||[])){
  for (const r of (run.results||[])){
    const rule = r.ruleId || (r.rule && r.rule.id) || 'unknown-rule';
    const msg = (r.message && r.message.text) || '';
    const locs = r.locations || [];
    if (!locs.length) continue;
    const phys = locs[0].physicalLocation || {};
    const uri = (phys.artifactLocation && phys.artifactLocation.uri) || '';
    const region = phys.region || {};
    const line = region.startLine || 0;
    findings.push({rule, file: uri, line, msg});
  }
}
let filtered = findings.filter(f => (!fileFilter || String(f.file).includes(fileFilter)) && (!ruleFilter || String(f.rule)===ruleFilter));
filtered.sort((a,b)=> (a.file.localeCompare(b.file) || a.line-b.line || a.rule.localeCompare(b.rule)));
console.log(`Total findings: ${filtered.length}${fileFilter?` (filtered by file: ${fileFilter})`:''}${ruleFilter?` (rule: ${ruleFilter})`:''}`);
let currentFile = null;
for (const f of filtered){
  if (f.file !== currentFile){
    currentFile = f.file;
    console.log(`\n== ${currentFile} ==`);
  }
  console.log(`${String(f.line).padStart(5,' ')}  [${f.rule}] ${f.msg}`);
}
