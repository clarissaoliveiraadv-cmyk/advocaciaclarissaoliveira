# Mapa do App Jurídico — Clarissa Oliveira Advocacia
**Data:** Abril 2026  
**Baseado em:** Sessão de levantamento de requisitos com a Clarissa

---

## 1. Fluxo de Cadastro (o jeito certo)

```
CONTATO criado
  └─► Dados básicos salvos
  └─► Botão "Vincular Processo"
        └─► Abre formulário do processo
        └─► Puxa nome/tel/email/CPF do contato automaticamente
        └─► Processo criado = Pasta criada
        └─► Contato continua existindo com link para a pasta
```

### Dados do Contato (obrigatórios)
- Nome completo
- Telefone
- E-mail
- CPF
- Endereço (para procuração)
- Indicação (quem indicou)
- **PIS** (obrigatório em processos trabalhistas)

### Dados Mínimos para Criar a Pasta (processo)
- Número CNJ
- Tribunal e Vara/Comarca
- Parte contrária

### Dados que completam depois (não bloqueiam o cadastro)
- Tipo de ação, pedidos, valor da causa, fase processual, honorários, etc.

---

## 2. Financeiro (o mais crítico)

### Princípio fundamental
**Lançar uma vez na pasta → aparece automaticamente no financeiro global.**  
Nunca lançar duas vezes.

### Três camadas do financeiro

**Camada 1 — Honorários Contratados (por pasta)**
- Modalidade: percentual de êxito, fixo mensal, entrada + parcelas, ou combinação
- Registrado na pasta no momento do contrato
- Gera parcelas automaticamente no financeiro global

**Camada 2 — Custas Reembolsáveis (por pasta)**
- Cada gasto adiantado pelo escritório (xerox, custas, motoboy) fica marcado como "a receber do cliente"
- No acerto final, o sistema lembra automaticamente: "Cobrar R$ X de custas"

**Camada 3 — Acerto de Contas (momento do alvará/acordo)**
- Você digita o valor total recebido
- O app calcula automaticamente:
  - Valor líquido do cliente
  - Honorários do escritório (% contratado)
  - Reembolso de custas antecipadas
- Gera extrato em PDF para enviar ao cliente pelo WhatsApp

### Perfis de acesso ao financeiro
- Clarissa, Advogados, Assistente → financeiro da pasta + financeiro global
- Estagiário → só financeiro da pasta
- Perfil Financeiro → só financeiro global

---

## 3. Central de Compromissos (agenda + prazos unificados)

### Princípio
Uma única tela. Dois tipos de evento. Filtros para separar quando necessário.

### Tipo 1 — Prazo Processual
- Contador regressivo visível: D-3, D-2, D-1
- Checkbox "Concluído" — só sai da tela quando marcado
- Vinculado obrigatoriamente a uma pasta
- Cor de alerta progressiva conforme se aproxima

### Tipo 2 — Audiência / Reunião
- Hora de início e hora de fim
- Local (endereço ou link Zoom/Teams)
- Bloqueia a agenda visualmente
- Lembrete de deslocamento (considerando trânsito BH)

### Filtros disponíveis
- Apenas Prazos (foco em escrita)
- Apenas Audiências (foco em deslocamento e preparação)
- Tudo (visão geral do dia)

### Ao criar novo evento
- Escolhe primeiro: Prazo ou Audiência/Reunião
- Se Prazo → pede data de vencimento + vincula processo
- Se Audiência → pede local/link + hora exata

---

## 4. Kanban + Tarefas do Dia (integrados)

### O problema atual
- Checklist diário: usado, mas é "curativo"
- Kanban: bonito mas vira cemitério de cards
- Os dois não se conversam

### Como deve funcionar
- **O Kanban alimenta o Checklist Diário** — não o contrário
- Cada card de processo tem um checklist interno de etapas (ex: Coletar documentos → Calcular FGTS → Redigir Inicial)
- A etapa atual do checklist interno gera a tarefa do dia automaticamente

### Sinalização de gargalo
- Card parado há mais de X dias na mesma coluna → muda de cor
- Visão de "onde o trabalho está travado" sem precisar perguntar para a equipe

### Tarefas do dia — melhorias necessárias
- Opção de **editar** tarefa existente (não existe hoje)
- Puxar automaticamente tudo que foi prometido: prazos, etapas de Kanban, compromissos do dia

---

## 5. Perfis de Acesso

| Perfil | O que vê |
|---|---|
| Clarissa | Tudo |
| Advogado / Assistente | Tudo |
| Estagiário | Tudo exceto financeiro global |
| Financeiro | Só financeiro global |

---

## 6. Prioridades de Correção (ordem de impacto)

1. **Financeiro** — o mais evitado, o que mais buga. Sem confiança aqui o app não substitui planilha.
2. **Fluxo Contato → Processo** — duplo trabalho eliminado libera tempo real todo dia.
3. **Central de Compromissos** — prazos e agenda juntos reduzem risco de erro.
4. **Kanban alimentando Checklist** — transforma o Kanban de cemitério em ferramenta real.
5. **Tarefas do dia puxando tudo** — completar o que já existe.

---

## 7. O que NÃO mudar agora
- Visual e identidade do app (está bom)
- Módulo de Auditoria (funciona)
- Calculadora de Prazos (funciona)
- Módulo de Contatos básico (base para o novo fluxo)

