# Esquema de Dados — Escritório Clarissa App
**Versão:** Abril 2026  
**Arquivo:** `Escritorio_Clarissa_App.html` (single-file HTML+CSS+JS)  
**Backend:** Supabase — tabela `escritorio_dados` (colunas: `chave`, `valor`)

---

## Regra de Ouro

> **Antes de adicionar qualquer funcionalidade que salva dados:**  
> 1. Verifique se a variável já existe na tabela abaixo  
> 2. Use a chave Supabase já definida — nunca crie uma nova chave para variável existente  
> 3. Chame `_salvarClienteLocal(obj)` sempre que criar um novo cliente/processo

---

## Tabela de Dados — Fonte Única de Verdade

| Variável JS | Tipo | Chave Supabase | O que guarda | Quem pode modificar |
|---|---|---|---|---|
| `CLIENTS` | Array | *(veja abaixo)* | Todos os processos/clientes | Apenas funções listadas abaixo |
| `tasks` | Object `{id: {...}}` | `co_tasks` | Dados extras por pasta: tel, email, CPF, honorários, parceiros | `novoProcesso`, `salvarAtendimento`, `atEvoluirParaProcesso` |
| `notes` | Object `{id: string}` | `co_notes` | Notas/observações por pasta | `novoProcesso`, `salvarNota`, `excluirProcesso` |
| `localAg` | Array | `co_ag` | Agenda/compromissos criados no app | `_abrirModalCompromisso`, `agendaConcluirComDesfecho`, `calcAdicionarAgenda` |
| `localMov` | Object `{id: Array}` | `co_mv` | Movimentações manuais por pasta | `editarMovimentacao`, `abrirModalMov`, `excluirProcesso` |
| `localLanc` | Array | `co_ln` | Lançamentos financeiros por pasta | `fmSalvar`, `finDelLanc`, `finBaixarLanc` |
| `finLancs` | Array | `co_fin` | Lançamentos financeiros globais (receber/pagar) | `vfEditarLanc`, `vfBaixar`, `vfDelGlobal` |
| `prazos` | Object `{id: Array}` | `co_prazos` | Prazos processuais por pasta | `calcSalvarPrazo`, `editarPrazo`, `deletarPrazo`, `_abrirModalCompromisso` |
| `tarefasDia` | Object `{data: Array}` | `co_td` | Checklist diário de tarefas | `hcToggle`, `hcRemover`, `hcEnviarKanban`, `novoTarefaDia` |
| `vkTasks` | Array | `co_vktasks` | Cards do Kanban | `vkSalvar`, `vkConcluirComDesfecho`, `hcEnviarKanban` |
| `localAtend` | Array | `co_atend` | Pipeline CRM — atendimentos | `atAlterarStatus`, `atEvoluirParaProcesso`, `salvarAtendimento` |
| `monteMor` | Array | `co_monte_mor` | Fluxo de caixa global | `_inserirMonteMor` |
| `encerrados` | Object `{id: true}` | `co_encerrados` | IDs de processos encerrados | `encerrarProcesso`, `excluirProcesso` |
| `localContatos` | Array | `co_ctc` | Contatos adicionados no app | `ctcSalvar`, `ctcDeletar` |
| `_auditLog` | Array | `co_audit` | Log de auditoria de ações | `audit()` — não chamar diretamente |
| `comentarios` | Object `{id: string}` | `co_coments` | Comentários internos por pasta | `salvarComentario` |
| `_colaboradores` | Array | `co_colab` | Lista de colaboradores do escritório | Configurações |
| `_despFixas` | Array | `co_despfixas` | Despesas fixas mensais | Configurações financeiras |
| `despesasProcesso` | Array | `co_desp_proc` | Despesas adiantadas por processo | `salvarDespesaProcesso` |

---

## CLIENTS — Regras Especiais (causa do bug histórico)

`CLIENTS` é reconstruído do zero a cada carga da página:

```
CLIENTS = [
  ...JSON inline do Projuris (~150 processos, ESTÁTICO),
  ...localStorage('co_consultas')  ← clientes criados pelo app
]
```

### Regra obrigatória
**Sempre que fizer `CLIENTS.push(novoCliente)`, chamar na linha seguinte:**
```js
_salvarClienteLocal(novoCliente);
```

Funções onde isso deve acontecer:
- `novoProcesso()` — criação de processo manual
- `atSelecionarCliente()` — novo cliente via pipeline
- `atEvoluirParaProcesso()` — atendimento virando processo

### Função `_salvarClienteLocal` (já existe no arquivo)
```js
function _salvarClienteLocal(novoCliente) {
  try {
    const consultas = JSON.parse(localStorage.getItem('co_consultas') || '[]');
    const idx = consultas.findIndex(c => String(c.id) === String(novoCliente.id));
    if (idx >= 0) consultas[idx] = novoCliente;
    else consultas.push(novoCliente);
    localStorage.setItem('co_consultas', JSON.stringify(consultas));
    sbSet('co_consultas', consultas);
  } catch(e) { console.warn('Erro ao salvar cliente local:', e); }
}
```

---

## Como os Dados Fluem

```
Carga da página
    └─► carregarDadosObj(d)
            ├─ CLIENTS = JSON Projuris + co_consultas (localStorage)
            ├─ tasks, notes, localAg, localMov... = localStorage (cada um na sua chave)
            └─ (se online) sbAplicar() sobrescreve com dados do Supabase

Usuário modifica dado
    └─► função específica modifica a variável JS
            └─► sbSet('co_chave', variavel)
                    ├─ salva no localStorage (imediato)
                    └─ salva no Supabase (se online)

Sincronização manual (botão sync)
    └─► sbForcaSync()
            └─ envia todas as variáveis para o Supabase
```

---

## Chaves que NÃO existem mais (aliases eliminados)

Estas chaves foram unificadas — **nunca recriar**:

| Chave eliminada | Usar em vez disso |
|---|---|
| `co_t` | `co_tasks` |
| `co_n` | `co_notes` |
| `co_enc` | `co_encerrados` |
| `co_localAg` | `co_ag` |
| `co_localMov` | `co_mv` |
| `co_localLanc` | `co_ln` |
| `co_localContatos` | `co_ctc` |
| `co_tarefasDia` | `co_td` |
| `co_td` para prazos | `co_prazos` |

---

## Checklist para Claude Code — Antes de Qualquer PR

- [ ] Nova funcionalidade usa chave existente da tabela acima?
- [ ] Se cria novo cliente/processo: `_salvarClienteLocal()` foi chamado?
- [ ] Nenhuma nova chave `co_` foi criada sem estar na tabela?
- [ ] Sintaxe válida: `node -e "new Function(require('fs').readFileSync('arquivo.html','utf8').match(/<script>([\s\S]*?)<\/script>/)[1]); console.log('OK')"`

