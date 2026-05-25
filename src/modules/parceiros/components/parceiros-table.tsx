import type { AdvogadoParceiro } from "@prisma/client";
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
import { toPercent } from "@/lib/money";

import { ParceiroFormDialog } from "./parceiro-form-dialog";
import { ParceiroDeleteDialog } from "./parceiro-delete-dialog";
import { ParceiroAtivoToggle } from "./parceiro-row-actions";
import { TIPO_PARCEIRO_LABELS } from "../schema";

type Props = { parceiros: AdvogadoParceiro[] };

export async function ParceirosTable({ parceiros }: Props) {
  if (parceiros.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhum parceiro encontrado.
      </div>
    );
  }

  const dependencias = await contarDependencias(parceiros.map((p) => p.id));

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Nome / OAB</TableHead>
            <TableHead>Tipo</TableHead>
            <TableHead className="text-right">% Sucumbência padrão</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {parceiros.map((p) => {
            const deps = dependencias.get(p.id) ?? {
              recebiveis: 0,
              parcerias: 0,
              sucumbencias: 0,
            };
            const podeExcluir =
              deps.recebiveis === 0 && deps.parcerias === 0 && deps.sucumbencias === 0;
            const motivos: string[] = [];
            if (deps.recebiveis > 0) motivos.push(`${deps.recebiveis} recebível(is)`);
            if (deps.parcerias > 0) motivos.push(`${deps.parcerias} parceria(s)`);
            if (deps.sucumbencias > 0) motivos.push(`${deps.sucumbencias} sucumbência(s)`);
            const motivoBloqueio =
              motivos.length > 0
                ? `Possui ${motivos.join(", ")} vinculados. Inative em vez de excluir.`
                : undefined;

            return (
              <TableRow key={p.id}>
                <TableCell>
                  <div className="font-medium">{p.nome}</div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {p.oab ? `OAB ${p.oab}` : "—"}
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant={badgeTipo(p.tipo)}>{TIPO_PARCEIRO_LABELS[p.tipo]}</Badge>
                </TableCell>
                <TableCell className="text-right font-mono text-sm">
                  {toPercent(p.percentualPadraoSucumbencia)}
                </TableCell>
                <TableCell>
                  <Badge variant={p.ativo ? "success" : "muted"}>
                    {p.ativo ? "Ativo" : "Inativo"}
                  </Badge>
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    <ParceiroFormDialog
                      modo="editar"
                      parceiroId={p.id}
                      initialValues={{
                        nome: p.nome,
                        tipo: p.tipo,
                        oab: p.oab ?? undefined,
                        percentualPadraoSucumbencia: percentualParaForm(
                          p.percentualPadraoSucumbencia,
                        ),
                      }}
                    />
                    <ParceiroAtivoToggle parceiroId={p.id} ativo={p.ativo} />
                    <ParceiroDeleteDialog
                      parceiroId={p.id}
                      rotulo={p.nome}
                      podeExcluir={podeExcluir}
                      motivoBloqueio={motivoBloqueio}
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

function badgeTipo(tipo: AdvogadoParceiro["tipo"]) {
  switch (tipo) {
    case "SOCIA":
      return "default" as const;
    case "PARCEIRO_EXTERNO":
      return "secondary" as const;
    case "FUNCIONARIO":
      return "outline" as const;
  }
}

/**
 * Converte a fração persistida (0..1) para a forma humana esperada pelo input
 * do formulário (0..100, sem o sinal "%"), preservando precisão.
 */
function percentualParaForm(
  value: AdvogadoParceiro["percentualPadraoSucumbencia"],
): string | undefined {
  if (value === null || value === undefined) return undefined;
  return value.mul(100).toString();
}

async function contarDependencias(
  ids: string[],
): Promise<Map<string, { recebiveis: number; parcerias: number; sucumbencias: number }>> {
  const result = new Map<string, { recebiveis: number; parcerias: number; sucumbencias: number }>();
  if (ids.length === 0) return result;

  const [recebiveis, parcerias, sucumbencias] = await Promise.all([
    prisma.recebivel.groupBy({
      by: ["parceiroId"],
      where: { parceiroId: { in: ids } },
      _count: true,
    }),
    prisma.parceriaPaga.groupBy({
      by: ["parceiroId"],
      where: { parceiroId: { in: ids } },
      _count: true,
    }),
    prisma.sucumbencia.groupBy({
      by: ["parceiroExternoId"],
      where: { parceiroExternoId: { in: ids } },
      _count: true,
    }),
  ]);

  for (const id of ids) result.set(id, { recebiveis: 0, parcerias: 0, sucumbencias: 0 });
  for (const g of recebiveis) {
    if (!g.parceiroId) continue;
    const cur = result.get(g.parceiroId);
    if (cur) cur.recebiveis = g._count;
  }
  for (const g of parcerias) {
    const cur = result.get(g.parceiroId);
    if (cur) cur.parcerias = g._count;
  }
  for (const g of sucumbencias) {
    if (!g.parceiroExternoId) continue;
    const cur = result.get(g.parceiroExternoId);
    if (cur) cur.sucumbencias = g._count;
  }

  return result;
}
