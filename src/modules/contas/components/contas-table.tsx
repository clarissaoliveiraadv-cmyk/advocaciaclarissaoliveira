import type { ContaBancaria } from "@prisma/client";
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
import { toBRL } from "@/lib/money";

import { ContaFormDialog } from "./conta-form-dialog";
import { ContaDeleteDialog } from "./conta-delete-dialog";
import { ContaAtivoToggle } from "./conta-row-actions";
import { TIPO_CONTA_LABELS } from "../schema";

type Props = { contas: ContaBancaria[] };

export async function ContasTable({ contas }: Props) {
  if (contas.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhuma conta encontrada.
      </div>
    );
  }

  const dependencias = await contarDependencias(contas.map((c) => c.id));

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Código / Nome</TableHead>
            <TableHead>Tipo</TableHead>
            <TableHead>Banco / Ag. / Conta</TableHead>
            <TableHead className="text-right">Saldo inicial</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {contas.map((c) => {
            const temLanc = dependencias.lanc.has(c.id);
            const podeExcluir = !temLanc && !dependencias.outras.has(c.id);
            return (
              <TableRow key={c.id}>
                <TableCell>
                  <div className="font-mono text-xs text-muted-foreground">{c.codigo}</div>
                  <div className="font-medium">{c.nome}</div>
                </TableCell>
                <TableCell className="text-sm">{TIPO_CONTA_LABELS[c.tipo]}</TableCell>
                <TableCell className="text-sm">
                  <div>{c.banco ?? "—"}</div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {[c.agencia, c.conta].filter(Boolean).join(" / ") || "—"}
                  </div>
                </TableCell>
                <TableCell className="text-right font-mono text-sm">
                  {toBRL(Number(c.saldoInicial))}
                </TableCell>
                <TableCell>
                  <Badge variant={c.ativo ? "success" : "muted"}>
                    {c.ativo ? "Ativa" : "Inativa"}
                  </Badge>
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    <ContaFormDialog
                      modo="editar"
                      contaId={c.id}
                      temLancamentos={temLanc}
                      initialValues={{
                        codigo: c.codigo,
                        nome: c.nome,
                        tipo: c.tipo,
                        banco: c.banco ?? undefined,
                        agencia: c.agencia ?? undefined,
                        conta: c.conta ?? undefined,
                        saldoInicial: Number(c.saldoInicial),
                      }}
                    />
                    <ContaAtivoToggle contaId={c.id} ativo={c.ativo} />
                    <ContaDeleteDialog contaId={c.id} rotulo={c.codigo} podeExcluir={podeExcluir} />
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

async function contarDependencias(
  ids: string[],
): Promise<{ lanc: Set<string>; outras: Set<string> }> {
  if (ids.length === 0) return { lanc: new Set(), outras: new Set() };

  const [lancamentos, recebimentos, repasses] = await Promise.all([
    prisma.lancamento.groupBy({ by: ["contaId"], where: { contaId: { in: ids } }, _count: true }),
    prisma.recebivel.groupBy({
      by: ["contaRecebimentoId"],
      where: { contaRecebimentoId: { in: ids } },
      _count: true,
    }),
    prisma.recebivel.groupBy({
      by: ["contaRepasseId"],
      where: { contaRepasseId: { in: ids } },
      _count: true,
    }),
  ]);

  const lanc = new Set<string>();
  for (const g of lancamentos) if (g.contaId) lanc.add(g.contaId);

  const outras = new Set<string>();
  for (const g of recebimentos) if (g.contaRecebimentoId) outras.add(g.contaRecebimentoId);
  for (const g of repasses) if (g.contaRepasseId) outras.add(g.contaRepasseId);

  return { lanc, outras };
}
