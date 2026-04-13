const fs = require('fs');

console.log('▸ Criando bundle.js a partir de app.js…');
if (!fs.existsSync('app.js')) { console.error('✗ app.js não existe'); process.exit(1); }
let appContent = fs.readFileSync('app.js', 'utf8');

const before = appContent;
appContent = appContent.replace("fetch('data-embedded.json?v=58')", "fetch('dados.json?v=59')");
appContent = appContent.replace('[carregarDados] data-embedded.json indisponível', '[carregarDados] dados.json indisponível');
if (appContent === before) { console.warn('  ⚠ fetch de data-embedded.json não encontrado'); }

fs.writeFileSync('bundle.js', appContent);
console.log('  ✓ bundle.js criado (' + fs.readFileSync('bundle.js').length + ' bytes)');

console.log('▸ Criando dados.json a partir de data-embedded.json…');
if (!fs.existsSync('data-embedded.json')) { console.error('✗ data-embedded.json não existe'); process.exit(1); }
const jsonContent = fs.readFileSync('data-embedded.json', 'utf8');
JSON.parse(jsonContent);
fs.writeFileSync('dados.json', jsonContent);
console.log('  ✓ dados.json criado (' + jsonContent.length + ' bytes)');

console.log('▸ Deletando app.js e data-embedded.json antigos…');
fs.unlinkSync('app.js');
fs.unlinkSync('data-embedded.json');
console.log('  ✓ deletados (git vai registrar como rename)');

console.log('▸ Atualizando index.html…');
let idx = fs.readFileSync('index.html', 'utf8');
idx = idx.replace('styles.css?v=58', 'styles.css?v=59');
idx = idx.replace('app.js?v=58', 'bundle.js?v=59');
fs.writeFileSync('index.html', idx);
console.log('  ✓ index.html: v58 → v59 + app.js → bundle.js');

console.log('▸ Atualizando sw.js…');
let sw = fs.readFileSync('sw.js', 'utf8');
sw = sw.replace("'co-advocacia-v58'", "'co-advocacia-v59'");
sw = sw.replace("'./app.js'", "'./bundle.js'");
sw = sw.replace("'./data-embedded.json'", "'./dados.json'");
fs.writeFileSync('sw.js', sw);
console.log('  ✓ sw.js: v58 → v59 + precache de bundle.js / dados.json');

console.log('▸ Validando sintaxe bundle.js…');
const { execSync } = require('child_process');
try { execSync('node --check bundle.js', { stdio: 'pipe' }); console.log('  ✓ bundle.js sintaxe OK'); }
catch (e) { console.error('  ✗ bundle.js sintaxe ERRO:', e.stderr?.toString()); process.exit(1); }

console.log('\n✓ Tudo pronto. Volta no GitHub Desktop, vai aparecer:');
console.log('  • app.js (deletado) → bundle.js (novo)');
console.log('  • data-embedded.json (deletado) → dados.json (novo)');
console.log('  • index.html, sw.js (modificados)');

