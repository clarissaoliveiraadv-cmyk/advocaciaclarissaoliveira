import { ArrowLeftRight, ExternalLink, Lock } from "lucide-react";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { toBRL } from "@/lib/money";
import { formatDataBR } from "@/lib/datas";

import { LancamentoFormDialog } from "./lancamento-form-dialog";
import { LancamentoDeleteDialog } from "./lancamento-delete-dialog";
import { TransferenciaFormDialog } from "./transferencia-form-dialog";
import type {
  CategoriaOpcao,
  ClienteOpcao,
  ContaOpcao,
  LancamentoComRelacoes,
  ProcessoOpcao,
} from "../queries";

type Props = {
  lancamentos: LancamentoComRelacoes[];
  contas: ContaOpcao[];
  categorias: CategoriaOpcao[];
  clientes: ClienteOpcao[];
  processos: ProcessoOpcao[];
};

export function LancamentosTable({ lancamentos, contas, categorias, clientes, processos }: Props) {
  if (lancamentos.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhum lançamento no período. Use o botão &quot;Novo lançamento&quot; para começar.
      </div>
    );
  }

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Data</TableHead>
            <TableHead>Descrição</TableHead>
            <TableHead>Conta</TableHead>
            <TableHead>Categoria</TableHead>
            <TableHead className="text-right">Valor</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {lancamentos.map((l) => {
            const ehTransferencia = !!l.transferenciaParId;
            const vinculadoARecebivel = !!l.recebivelId;
            const vinculadoARessarcimento = !!l.ressarcimentoId;
            const somenteLeitura = vinculadoARecebivel || vinculadoARessarcimento;
            const valorClass =
              l.tipo === "ENTRADA" ? "text-emerald-700 font-mono" : "text-red-700 font-mono";
            const sinal = l.tipo === "ENTRADA" ? "+" : "−";

            return (
              <TableRow key={l.id}>
                <TableCell className="font-mono text-xs">{formatDataBR(l.data)}</TableCell>
                <TableCell>
                  <div className="font-medium">{l.descricao}</div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                    {ehTransferencia && l.transferenciaPar && (
                      <Badge variant="outline" className="gap-1">
                        <ArrowLeftRight className="h-3 w-3" />
                        Transferência ↔ {l.transferenciaPar.conta.codigo}
                      </Badge>
                    )}
                    {vinculadoARecebivel && (
                      <Badge variant="muted" className="gap-1">
                        <Lock className="h-3 w-3" />
                        Recebível
                      </Badge>
                    )}
                    {vinculadoARessarcimento && (
                      <Badge variant="muted" className="gap-1">
                        <Lock className="h-3 w-3" />
                        Ressarcimento
                      </Badge>
                    )}
                    {l.cliente && <span>· {l.cliente.nome}</span>}
                    {l.comprovanteUrl && (
                      <a
                        href={l.comprovanteUrl}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex items-center gap-1 text-primary hover:underline"
                      >
                        <ExternalLink className="h-3 w-3" />
                        comprovante
                      </a>
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-sm">
                  <div className="font-mono text-xs text-muted-foreground">{l.conta.codigo}</div>
                  <div>{l.conta.nome}</div>
                </TableCell>
                <TableCell className="text-sm">
                  <div>{l.categoria.nome}</div>
                  {l.categoria.isPessoal && (
                    <div className="text-xs text-muted-foreground">Pessoal</div>
                  )}
                </TableCell>
                <TableCell className={cn("text-right tabular-nums", valorClass)}>
                  {sinal} {toBRL(Number(l.valor))}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    {renderEditar({
                      l,
                      contas,
                      categorias,
                      clientes,
                      processos,
                      somenteLeitura,
                      ehTransferencia,
                    })}
                    <LancamentoDeleteDialog
                      lancamentoId={l.id}
                      rotulo={l.descricao}
                      ehTransferencia={ehTransferencia}
                      podeExcluir={!somenteLeitura}
                      motivoBloqueio={
                        vinculadoARecebivel
                          ? "Lançamento vinculado a um recebível. Edite/exclua no módulo Recebíveis."
                          : vinculadoARessarcimento
                            ? "Lançamento vinculado a um ressarcimento. Edite/exclua no módulo Ressarcimento."
                            : undefined
                      }
                    />
                  </div>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

function renderEditar(args: {
  l: LancamentoComRelacoes;
  contas: ContaOpcao[];
  categorias: CategoriaOpcao[];
  clientes: ClienteOpcao[];
  processos: ProcessoOpcao[];
  somenteLeitura: boolean;
  ehTransferencia: boolean;
}) {
  const { l, contas, categorias, clientes, processos, somenteLeitura, ehTransferencia } = args;

  if (somenteLeitura) return null;

  if (ehTransferencia && l.transferenciaPar) {
    const saidaConta = l.tipo === "SAIDA" ? l.contaId : l.transferenciaPar.contaId;
    const entradaConta = l.tipo === "ENTRADA" ? l.contaId : l.transferenciaPar.contaId;
    return (
      <TransferenciaFormDialog
        modo="editar"
        pernaId={l.id}
        contas={contas}
        categorias={categorias}
        initialValues={{
          data: l.data.toISOString().slice(0, 10),
          descricao: l.descricao,
          contaOrigemId: saidaConta,
          contaDestinoId: entradaConta,
          categoriaId: l.categoriaId,
          valor: Number(l.valor),
          observacoes: l.observacoes ?? undefined,
        }}
      />
    );
  }

  if (l.tipo === "ENTRADA" || l.tipo === "SAIDA") {
    return (
      <LancamentoFormDialog
        modo="editar"
        lancamentoId={l.id}
        contas={contas}
        categorias={categorias}
        clientes={clientes}
        processos={processos}
        initialValues={{
          data: l.data.toISOString().slice(0, 10),
          descricao: l.descricao,
          tipo: l.tipo,
          contaId: l.contaId,
          categoriaId: l.categoriaId,
          valor: Number(l.valor),
          clienteId: l.clienteId ?? undefined,
          processoId: l.processoId ?? undefined,
          comprovanteUrl: l.comprovanteUrl ?? undefined,
          observacoes: l.observacoes ?? undefined,
        }}
      />
    );
  }
  return null;
}
