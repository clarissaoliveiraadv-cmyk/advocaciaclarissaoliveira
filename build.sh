#!/bin/bash
# Phase 4: Script de minificação simples (sem dependências externas)
# Uso: bash build.sh
# Saída: dist/ com arquivos minificados

set -e
mkdir -p dist

echo "→ Minificando CSS..."
# Remove comentários /* ... */, linhas vazias, espaços desnecessários
sed -E '
  s|/\*[^*]*\*+([^/*][^*]*\*+)*/||g
  s/^[[:space:]]+//
  s/[[:space:]]+$//
  /^$/d
  s/[[:space:]]*\{[[:space:]]*/\{/g
  s/[[:space:]]*\}[[:space:]]*/\}/g
  s/[[:space:]]*:[[:space:]]*/:/g
  s/[[:space:]]*;[[:space:]]*/;/g
' styles.css > dist/styles.css

echo "→ Minificando JS..."
# Remove comentários // de linha inteira e linhas vazias
sed -E '
  /^[[:space:]]*\/\//d
  s/^[[:space:]]+//
  /^$/d
' app.js > dist/app.js

echo "→ Copiando HTML e SW..."
cp "Escritorio_Clarissa_App_v2 (1).html" dist/index.html
cp sw.js dist/sw.js

# Atualizar referências no index.html
sed -i 's|Escritorio_Clarissa_App_v2 (1).html|index.html|g' dist/sw.js

# Relatório de tamanho
echo ""
echo "═══ Relatório de build ═══"
echo "Original:"
du -sh styles.css app.js "Escritorio_Clarissa_App_v2 (1).html" sw.js 2>/dev/null
echo ""
echo "Minificado (dist/):"
du -sh dist/styles.css dist/app.js dist/index.html dist/sw.js 2>/dev/null
echo ""
ORIG=$(cat styles.css app.js "Escritorio_Clarissa_App_v2 (1).html" sw.js | wc -c)
MINI=$(cat dist/styles.css dist/app.js dist/index.html dist/sw.js | wc -c)
PERC=$((100 - MINI * 100 / ORIG))
echo "Redução total: ${PERC}%"
echo "Pronto! Arquivos em dist/"
