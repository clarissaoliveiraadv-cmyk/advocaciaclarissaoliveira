#!/usr/bin/env node
/**
 * Build / versionamento - Clarissa Oliveira Advocacia (PWA)
 *
 * Fonte unica da versao: package.json -> "assetVersion".
 * Este script propaga essa versao para todos os pontos onde o
 * navegador precisa invalidar cache:
 *
 *   index.html  ->  styles.css?v=N
 *                   repos/agenda.js?v=N
 *                   repos/prazos.js?v=N
 *                   bundle.js?v=N
 *   sw.js       ->  CACHE_NAME 'co-advocacia-vN'
 *                   precache  './styles.css?v=N'
 *                   precache  './repos/agenda.js?v=N'
 *                   precache  './repos/prazos.js?v=N'
 *                   precache  './bundle.js?v=N'
 *   bundle.js   ->  fetch('dados.json?v=N')
 *
 * Uso:
 *   node apply.js              propaga assetVersion atual
 *   node apply.js --bump       incrementa assetVersion em +1 e propaga
 *   node apply.js --set 130    define assetVersion = 130 e propaga
 *
 * Sempre roda `node --check` em bundle.js e nos repos.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = __dirname;
const PKG_PATH = path.join(ROOT, 'package.json');

// ---------------- 1. Resolver versao alvo ----------------
const argv = process.argv.slice(2);
const pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));
let target = Number(pkg.assetVersion);

if (argv.includes('--bump')) {
  target = (Number.isFinite(target) ? target : 0) + 1;
} else {
  const i = argv.indexOf('--set');
  if (i >= 0) {
    const n = Number(argv[i + 1]);
    if (!Number.isFinite(n) || n <= 0) {
      console.error('[ERRO] --set requer numero inteiro positivo');
      process.exit(1);
    }
    target = n;
  }
}

if (!Number.isFinite(target) || target <= 0) {
  console.error('[ERRO] assetVersion invalido em package.json (esperado numero > 0).');
  process.exit(1);
}

console.log('-> Versao alvo: v' + target);

// ---------------- 2. Patch util ----------------
function patch(file, label, transforms) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full)) {
    console.error('[ERRO] ' + file + ' nao existe - abortando.');
    process.exit(1);
  }
  let txt = fs.readFileSync(full, 'utf8');
  let total = 0;
  for (const t of transforms) {
    let count = 0;
    txt = txt.replace(t.re, function (m) { count++; return t.replace; });
    total += count;
  }
  fs.writeFileSync(full, txt);
  console.log('   OK ' + file + ' - ' + total + ' substituicao(oes) [' + label + ']');
  return total;
}

const v = String(target);

// ---------------- 3. Aplicar em cada arquivo ----------------
console.log('-> Atualizando index.html...');
patch('index.html', 'CSS + JS + repos', [
  { re: /styles\.css\?v=\d+/g,        replace: 'styles.css?v=' + v },
  { re: /bundle\.js\?v=\d+/g,         replace: 'bundle.js?v=' + v },
  { re: /repos\/agenda\.js\?v=\d+/g,  replace: 'repos/agenda.js?v=' + v },
  { re: /repos\/prazos\.js\?v=\d+/g,  replace: 'repos/prazos.js?v=' + v },
]);

console.log('-> Atualizando sw.js...');
patch('sw.js', 'CACHE_NAME + precache', [
  { re: /'co-advocacia-v\d+'/g,       replace: "'co-advocacia-v" + v + "'" },
  { re: /styles\.css\?v=\d+/g,        replace: 'styles.css?v=' + v },
  { re: /bundle\.js\?v=\d+/g,         replace: 'bundle.js?v=' + v },
  { re: /repos\/agenda\.js\?v=\d+/g,  replace: 'repos/agenda.js?v=' + v },
  { re: /repos\/prazos\.js\?v=\d+/g,  replace: 'repos/prazos.js?v=' + v },
]);

console.log('-> Atualizando bundle.js (fetch de dados.json)...');
patch('bundle.js', 'fetch dados.json', [
  { re: /dados\.json\?v=\d+/g, replace: 'dados.json?v=' + v },
]);

// ---------------- 4. Persistir versao em package.json ----------------
pkg.assetVersion = target;
fs.writeFileSync(PKG_PATH, JSON.stringify(pkg, null, 2) + '\n');
console.log('-> package.json: assetVersion = ' + target);

// ---------------- 5. Validar sintaxe do bundle e dos repos ----------------
console.log('-> Validando sintaxe...');
const checks = ['bundle.js', 'repos/agenda.js', 'repos/prazos.js'];
for (const f of checks) {
  try {
    execSync('node --check ' + JSON.stringify(f), { cwd: ROOT, stdio: 'pipe' });
    console.log('   OK ' + f);
  } catch (e) {
    console.error('   [ERRO] ' + f + ' sintaxe ERRO:');
    console.error(e.stderr ? e.stderr.toString() : e.message);
    process.exit(1);
  }
}

console.log('');
console.log('OK Versao v' + target + ' propagada com sucesso.');
console.log('   Proximos passos:');
console.log('     1. git add -A');
console.log('     2. git commit -m "chore: bump assets to v' + target + '"');
console.log('     3. git push   (GitHub Pages publica em ~1 min)');
