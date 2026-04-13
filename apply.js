const fs = require('fs');
function readLines(path) { return fs.readFileSync(path, 'utf8').split('\n'); }
function writeLines(path, lines) { fs.writeFileSync(path, lines.join('\n')); }

console.log('▸ Lendo app.js…');
let appLines = readLines('app.js');

const carregarIdx = appLines.findIndex(l => l.startsWith('async function carregarDados('));
if (carregarIdx === -1) { console.error('✗ função carregarDados() não encontrada'); process.exit(1); }

const dataLineIdx = carregarIdx + 2;
const dataLine = appLines[dataLineIdx];
if (!dataLine || !dataLine.includes('const d = {')) {
  console.error('✗ linha esperada não bate. Início:', JSON.stringify((dataLine||'').slice(0, 100)));
  process.exit(1);
}

console.log('▸ Extraindo JSON embutido…');
const start = dataLine.indexOf('{');
const end = dataLine.lastIndexOf('};');
const jsonText = dataLine.slice(start, end + 1);
JSON.parse(jsonText);
fs.writeFileSync('data-embedded.json', jsonText);
console.log('  ✓ data-embedded.json criado (' + jsonText.length + ' bytes)');

const newFunc =
  'async function carregarDados(){\n' +
  '  // Dados embutidos extraídos para data-embedded.json (reduzir tamanho do app.js)\n' +
  '  // Fallback: objeto vazio se o JSON falhar (Supabase preenche depois)\n' +
  '  let d = {versao:"1.0", clientes:[], agenda:[], all_lanc:[], mutavel:{}, financeiro_xlsx:[], despesas_processo:[]};\n' +
  '  try {\n' +
  '    const r = await fetch(\'data-embedded.json?v=58\');\n' +
  '    if(r.ok) d = await r.json();\n' +
  '  } catch(e) { console.warn(\'[carregarDados] data-embedded.json indisponível:\', e.message); }\n' +
  '  carregarDadosObj(d);\n' +
  '}';
appLines.splice(carregarIdx, 5, ...newFunc.split('\n'));
console.log('  ✓ função carregarDados() substituída');

const initCallIdx = appLines.findIndex(l => l.includes('carregarDados(); // carrega dados embutidos'));
if (initCallIdx === -1) { console.error('✗ chamada de carregarDados() em init() não encontrada'); process.exit(1); }
appLines[initCallIdx] = '  await carregarDados(); // carrega dados embutidos via fetch — precisa de await agora';
console.log('  ✓ await adicionado em init()');

writeLines('app.js', appLines);
console.log('  ✓ app.js: ' + fs.readFileSync('app.js').length + ' bytes');

console.log('▸ Atualizando sw.js…');
let sw = fs.readFileSync('sw.js', 'utf8');
sw = sw.replace("'co-advocacia-v57'", "'co-advocacia-v58'");
sw = sw.replace("  './app.js',\n  './manifest.json'", "  './app.js',\n  './data-embedded.json',\n  './manifest.json'");
fs.writeFileSync('sw.js', sw);
console.log('  ✓ sw.js atualizado');

console.log('▸ Atualizando index.html…');
let idx = fs.readFileSync('index.html', 'utf8');
idx = idx.replace('styles.css?v=57', 'styles.css?v=58');
idx = idx.replace('app.js?v=57', 'app.js?v=58');
fs.writeFileSync('index.html', idx);
console.log('  ✓ index.html atualizado');

console.log('▸ Validando sintaxe…');
const { execSync } = require('child_process');
try { execSync('node --check app.js', { stdio: 'pipe' }); console.log('  ✓ app.js sintaxe OK'); }
catch (e) { console.error('  ✗ app.js sintaxe ERRO:', e.stderr?.toString()); process.exit(1); }

console.log('\n✓ Tudo pronto. Agora roda:');
console.log('  git add app.js sw.js index.html data-embedded.json');
console.log('  git commit -m "perf: extrair dados embutidos para data-embedded.json"');
console.log('  git push');
