import { prisma } from "@/lib/prisma";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { formatCnj } from "@/lib/format";

import { ProcessoFormDialog } from "./processo-form-dialog";
import { ProcessoDeleteDialog } from "./processo-delete-dialog";
import { ProcessoAtivoToggle } from "./processo-row-actions";
import type { ClienteOpcao } from "./cliente-combobox";
import type { ProcessoComCliente } from "../queries";
import { NATUREZA_LABELS, STATUS_LABELS } from "../schema";

type Props = {
  processos: ProcessoComCliente[];
  clientes: ClienteOpcao[];
};

export async function ProcessosTable({ processos, clientes }: Props) {
  if (processos.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhum processo encontrado.
      </div>
    );
  }

  const dependencias = await contarDependencias(processos.map((p) => p.id));

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Cliente / Nº CNJ</TableHead>
            <TableHead>Natureza</TableHead>
            <TableHead>Vara / Tribunal</TableHead>
            <TableHead>Parte contrária</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {processos.map((p) => (
            <TableRow key={p.id}>
              <TableCell>
                <div className="font-medium">{p.cliente.nome}</div>
                <div className="font-mono text-xs text-muted-foreground">
                  {p.numeroCnj ? formatCnj(p.numeroCnj) : "— sem CNJ —"}
                </div>
              </TableCell>
              <TableCell className="text-sm">{NATUREZA_LABELS[p.natureza]}</TableCell>
              <TableCell className="text-sm">
                <div>{p.vara ?? "—"}</div>
                <div className="text-xs text-muted-foreground">{p.tribunal ?? ""}</div>
              </TableCell>
              <TableCell className="text-sm">{p.parteContraria ?? "—"}</TableCell>
              <TableCell>
                <div className="flex flex-col gap-1">
                  <Badge variant={statusVariant(p.status)}>{STATUS_LABELS[p.status]}</Badge>
                  {!p.ativo && (
                    <Badge variant="muted" className="w-fit">
                      Inativo
                    </Badge>
                  )}
                </div>
              </TableCell>
              <TableCell>
                <div className="flex items-center justify-end gap-1">
                  <ProcessoFormDialog
                    modo="editar"
                    processoId={p.id}
                    clientes={clientes}
                    initialValues={{
                      clienteId: p.clienteId,
                      numeroCnj: p.numeroCnj ?? undefined,
                      natureza: p.natureza,
                      status: p.status,
                      vara: p.vara ?? undefined,
                      tribunal: p.tribunal ?? undefined,
                      parteContraria: p.parteContraria ?? undefined,
                      observacoes: p.observacoes ?? undefined,
                    }}
                  />
                  <ProcessoAtivoToggle processoId={p.id} ativo={p.ativo} />
                  <ProcessoDeleteDialog
                    processoId={p.id}
                    rotulo={p.numeroCnj ? formatCnj(p.numeroCnj) : p.cliente.nome}
                    podeExcluir={!dependencias.has(p.id)}
                  />
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function statusVariant(s: ProcessoComCliente["status"]) {
  switch (s) {
    case "EM_ANDAMENTO":
      return "success" as const;
    case "SUSPENSO":
      return "outline" as const;
    case "ENCERRADO":
      return "secondary" as const;
    case "ARQUIVADO":
      return "muted" as const;
  }
}

async function contarDependencias(ids: string[]): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const [recebiveis, lancamentos, ressarcimentos, sucumbencias, parcerias] = await Promise.all([
    prisma.recebivel.groupBy({
      by: ["processoId"],
      where: { processoId: { in: ids } },
      _count: true,
    }),
    prisma.lancamento.groupBy({
      by: ["processoId"],
      where: { processoId: { in: ids } },
      _count: true,
    }),
    prisma.ressarcimento.groupBy({
      by: ["processoId"],
      where: { processoId: { in: ids } },
      _count: true,
    }),
    prisma.sucumbencia.groupBy({
      by: ["processoId"],
      where: { processoId: { in: ids } },
      _count: true,
    }),
    prisma.parceriaPaga.groupBy({
      by: ["processoId"],
      where: { processoId: { in: ids } },
      _count: true,
    }),
  ]);
  const set = new Set<string>();
  for (const g of [
    ...recebiveis,
    ...lancamentos,
    ...ressarcimentos,
    ...sucumbencias,
    ...parcerias,
  ]) {
    if (g.processoId) set.add(g.processoId);
  }
  return set;
}
