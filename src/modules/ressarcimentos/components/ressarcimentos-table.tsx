import { StatusRessarcimento } from "@prisma/client";

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
import { formatDataBR } from "@/lib/datas";
import { formatCnj } from "@/lib/format";

import { RessarcimentoFormDialog } from "./ressarcimento-form-dialog";
import { RessarcimentoDeleteDialog } from "./ressarcimento-delete-dialog";
import {
  MarcarReembolsadoDialog,
  ReverterReembolsoButton,
} from "./ressarcimento-row-actions";
import { STATUS_RESSARCIMENTO_LABELS } from "../schema";
import type { ProcessoOpcao, RessarcimentoComRelacoes } from "../queries";

type Props = {
  ressarcimentos: RessarcimentoComRelacoes[];
  processos: ProcessoOpcao[];
};

export function RessarcimentosTable({ ressarcimentos, processos }: Props) {
  if (ressarcimentos.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhum ressarcimento encontrado no período/filtro selecionado.
      </div>
    );
  }

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Data</TableHead>
            <TableHead>Cliente / Processo</TableHead>
            <TableHead>Descrição</TableHead>
            <TableHead className="text-right">Valor</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="w-[100px]">Reembolso</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {ressarcimentos.map((r) => {
            const valor = Number(r.valor);
            const ehReembolsado = r.status === StatusRessarcimento.REEMBOLSADO;

            return (
              <TableRow key={r.id}>
                <TableCell className="font-mono text-xs">{formatDataBR(r.data)}</TableCell>
                <TableCell>
                  <div className="font-medium">{r.cliente.nome}</div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {r.processo.numeroCnj ? formatCnj(r.processo.numeroCnj) : "— sem CNJ —"}
                  </div>
                </TableCell>
                <TableCell className="text-sm">{r.descricao}</TableCell>
                <TableCell className="text-right font-mono tabular-nums">{toBRL(valor)}</TableCell>
                <TableCell>
                  <Badge variant={ehReembolsado ? "success" : "outline"}>
                    {STATUS_RESSARCIMENTO_LABELS[r.status]}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {r.dataReembolso ? formatDataBR(r.dataReembolso) : "—"}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    {ehReembolsado ? (
                      <ReverterReembolsoButton id={r.id} />
                    ) : (
                      <>
                        <MarcarReembolsadoDialog id={r.id} />
                        <RessarcimentoFormDialog
                          modo="editar"
                          ressarcimentoId={r.id}
                          processos={processos}
                          initialValues={{
                            processoId: r.processoId,
                            data: r.data.toISOString().slice(0, 10),
                            descricao: r.descricao,
                            valor: Number(r.valor),
                            recebivelId: r.recebivelId ?? undefined,
                          }}
                        />
                        <RessarcimentoDeleteDialog
                          id={r.id}
                          rotulo={`${r.cliente.nome} · ${toBRL(valor)}`}
                        />
                      </>
                    )}
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
