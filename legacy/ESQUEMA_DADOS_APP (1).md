# Esquema de Dados — Escritório Clarissa App
**Versão:** Abril 2026 (atualizado após auditoria completa)  
**Arquivo principal:** `bundle.js` (extraído de `index.html`)  
**Backend:** Supabase — tabela `escritorio_dados` (colunas: `chave`, `valor`, `updated_at`, `updated_by`, `_session_id`)

---

## Regra de Ouro

> **Antes de adicionar qualquer funcionalidade que salva dados:**  
> 1. Verifique se a variável já existe na tabela abaixo  
> 2. Use a chave Supabase já definida — nunca crie uma nova chave para variável existente  
> 3. Sempre chame `sbSalvarClientesDebounced()` após `CLIENTS.push(novoCliente)`  
> 4. Use `sbSet('co_CHAVE', variavel)` para salvar — ele faz localStorage imediato + POST debounced  
> 5. Chame `marcarAlterado()` após qualquer mutação de dados

---

## Tabela de Dados — Fonte Única de Verdade

| Variável JS | Tipo | Chave Supabase | O que guarda |
|---|---|---|---|
| `CLIENTS` | Array | `co_clientes` | Todos os processos/clientes (Projuris + criados no app) |
| `tasks` | Object `{id: {...}}` | `co_tasks` | Dados extras por pasta: tel, email, CPF, honorários, parceiros |
| `notes` | Object `{id: string}` | `co_notes` | Notas/observações por pasta |
| `localAg` | Array | `co_ag` | Agenda/compromissos criados no app |
| `localMov` | Object `{id: Array}` | `co_localMov` | Movimentações/andamentos manuais por pasta |
| `localLanc` | Array | `co_localLanc` | Lançamentos financeiros por pasta (honorários, despesas, repasses) |
| `finLancs` | Array | `co_fin` | Lançamentos financeiros globais do escritório (despesas fixas, alvarás) |
| `prazos` | Object `{id: Array}` | `co_prazos` | Prazos processuais por pasta |
| `tarefasDia` | Object `{data: Array}` | `co_td` | Checklist diário de tarefas (legado) |
| `vkTasks` | Array | `co_vktasks` | Cards do Kanban |
| `localAtend` | Array | `co_atend` | Pipeline CRM — atendimentos |
| `monteMor` | Array | `co_monte_mor` | Fluxo de caixa global |
| `encerrados` | Object `{id: true}` | `co_encerrados` | IDs de processos encerrados/arquivados |
| `localContatos` | Array | `co_ctc` | Contatos adicionados no app |
| `_auditLog` | Array | `co_audit` | Log de auditoria de ações |
| `comentarios` | Object `{id: string}` | `co_coments` | Comentários internos por pasta |
| `_colaboradores` | Array | `co_colab` | Lista de colaboradores do escritório |
| `_despFixas` | Array | `co_despfixas` | Despesas fixas mensais (templates) |
| `despesasProcesso` | Array | `co_desp_proc` | Despesas adiantadas por processo (reembolso) |
| `_iniciais` | Array | `co_iniciais` | Pipeline de petições iniciais |

---

## CLIENTS — Como Funciona

`CLIENTS` é carregado em 2 etapas no boot:

```
1. carregarDadosObj(d)
   └─ CLIENTS = dados embutidos do Projuris (~150 processos, ESTÁTICO no dados.json)

2. sbInit() → sbCarregarTudo() → sbCarregarClientes()
   └─ Busca co_clientes do Supabase
   └─ Merge: _sbMergeArrays(CLIENTS, remoto, 'co_clientes')
   └─ montarClientesAgrupados() → renumera pastas
```

### Regra para criar novo cliente/processo
**Sempre que fizer `CLIENTS.push(novoCliente)`, chamar na linha seguinte:**
```js
sbSalvarClientesDebounced();
```

Isso:
1. Salva no localStorage **imediatamente** (proteção contra perda)
2. Agenda POST ao Supabase (debounce 200ms + 300ms)

Funções que criam clientes (já verificadas na auditoria):
- `novoProcesso()` — L8181 ✓
- `atSalvarNovoCliente()` — L9549, L9590 ✓
- `converterEmProcesso()` — L9696 (não faz push, muta in-place) ✓
- `atEvoluirParaProcesso()` — L15838 ✓

---

## Mecanismos de Proteção de Dados

### 1. Save imediato no localStorage
`sbSetDebounced()` faz `lsSet()` **antes** de agendar o timer.
Janela de perda de dados: 0ms para localStorage, ~500ms para Supabase.

### 2. beforeunload flush
Quando a aba fecha, `_sbSetPending` é flushed via `navigator.sendBeacon`.

### 3. Tombstones (anti-zombificação)
Itens deletados de `co_fin` e `co_localLanc` têm seus IDs registrados em:
- `co_fin_del` — IDs de finLancs deletados
- `co_localLanc_del` — IDs de localLanc deletados
- `co_projuris_del` — chaves `_migrado_projuris|tipo` de itens do seed deletados

O `_sbMergeArrays` filtra esses IDs antes de mergear, impedindo ressurreição.

### 4. Cooldown no Realtime (5s)
Após salvar `co_localMov`, `co_coments` ou `co_notes`, eventos Realtime para essas chaves são ignorados por 5 segundos. Sem isso, o Realtime re-inseria itens deletados.

### 5. Read-modify-write no sbSet
Para chaves de array (`co_fin`, `co_localLanc`, `co_clientes`, etc.), antes do POST:
1. GET remoto atual
2. Merge com local via `_sbMergeArrays`
3. POST resultado merged

### 6. Watchdog de reconexão (30s)
Se `_sbOnline=false`, tenta `sbCarregarTudo()` automaticamente a cada 30 segundos.

---

## Como os Dados Fluem

```
Carga da página
    └─► carregarDadosObj(d) — dados estáticos do Projuris
    └─► sbInit() → sbCarregarTudo()
            ├─ Busca TODAS as chaves do Supabase
            ├─ Merge com localStorage local (tombstones respeitados)
            ├─ Aplica em memória (finLancs, localLanc, localMov, etc.)
            └─ sbRealtime() → WebSocket para updates em tempo real

Usuário modifica dado
    └─► função específica modifica a variável JS
            └─► sbSet('co_chave', variavel) ou sbSalvarClientesDebounced()
                    ├─ lsSet imediato (localStorage)
                    ├─ Read-modify-write (merge com remoto)
                    └─ POST ao Supabase

Outro PC modifica dado
    └─► WebSocket Realtime recebe evento
            └─► onmessage → _sbMerge(local, remoto)
                    ├─ Cooldown respeitado (co_localMov, co_coments, co_notes)
                    ├─ Tombstones respeitados (co_fin, co_localLanc)
                    └─► sbAplicar(chave, merged) → re-render automático da ficha/dashboard

Ressincronização forçada (F12 → Console)
    └─► coForceSync() — busca tudo do Supabase + reinicia Realtime
    └─► coDiagnose() — mostra contagem local vs remoto
```

---

## Chaves Eliminadas — NUNCA recriar

| Chave eliminada | Usar em vez disso | Motivo |
|---|---|---|
| `co_t` | `co_tasks` | Alias antigo, leitura só buscava `co_tasks` |
| `co_n` | `co_notes` | Alias antigo, leitura só buscava `co_notes` |
| `co_tarefasDia` | `co_td` | Alias antigo, sbInit lê `co_td` |
| `co_localAg` | `co_ag` | Alias antigo, consolidado para `co_ag` |
| `co_td` para **prazos** | `co_prazos` | `co_td` é exclusivo de `tarefasDia` |

**Chaves que NÃO foram renomeadas** (diferente do HTML single-file):
- `co_localMov` — continua sendo `co_localMov` (NÃO é `co_mv`)
- `co_localLanc` — continua sendo `co_localLanc` (NÃO é `co_ln`)

---

## Funções de Diagnóstico (F12 → Console)

| Comando | O que faz |
|---|---|
| `coDiagnose()` | Mostra contagem local vs remoto, divergências, tombstones |
| `coForceSync()` | Força ressincronização completa com o Supabase |
| `coVerEncerrados()` | Lista todos os processos marcados como encerrados |
| `coReativar(id)` | Desarquiva um processo específico |
| `coReativarTodos()` | Desarquiva todos os processos (usar com cuidado!) |

---

## Checklist para Claude Code — Antes de Qualquer PR

- [ ] Nova funcionalidade usa chave existente da tabela acima?
- [ ] Se cria novo cliente/processo: `sbSalvarClientesDebounced()` chamado após `CLIENTS.push`?
- [ ] Nenhuma chave `co_` nova criada sem estar na tabela?
- [ ] `marcarAlterado()` chamado após mutação de dados?
- [ ] Re-render chamado após `sbSet` (vfRender, renderFicha, doSearch, etc.)?
- [ ] Deleção de finLancs/localLanc chama `_tombstoneAdd()`?
- [ ] Sintaxe válida: `node --check bundle.js`
