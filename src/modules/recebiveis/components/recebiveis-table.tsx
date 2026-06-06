import { StatusRecebivel } from "@prisma/client";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { toBRL, toPercent } from "@/lib/money";
import { formatDataBR } from "@/lib/datas";
import { formatCnj } from "@/lib/format";

import { RecebivelFormDialog } from "./recebivel-form-dialog";
import { RecebivelDeleteDialog } from "./recebivel-delete-dialog";
import { RecebivelCancelToggle } from "./recebivel-row-actions";
import { STATUS_RECEBIVEL_LABELS, TIPO_PARCELA_LABELS } from "../schema";
import type { ParceiroOpcao, ProcessoOpcao, RecebivelComRelacoes } from "../queries";

type Props = {
  recebiveis: RecebivelComRelacoes[];
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
};

export function RecebiveisTable({ recebiveis, processos, parceiros }: Props) {
  if (recebiveis.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhum recebível encontrado no período/filtro selecionado.
      </div>
    );
  }

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Data prev.</TableHead>
            <TableHead>Cliente / Processo</TableHead>
            <TableHead>Parcela</TableHead>
            <TableHead className="text-right">Valor parcela</TableHead>
            <TableHead className="text-right">Honor. sug.</TableHead>
            <TableHead className="text-right">Cliente sug.</TableHead>
            <TableHead>Parceria</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {recebiveis.map((r) => {
            const valorParcela = Number(r.valorParcela);
            const ressarc = Number(r.ressarcimentoEmbutido);
            const ph = Number(r.percHonorarios);
            const honor = valorParcela * ph;
            const valorCliente = Math.max(0, valorParcela - ressarc - honor);
            const ehPrevista = r.status === StatusRecebivel.PREVISTA;
            const ehCancelada = r.status === StatusRecebivel.CANCELADA;
            const podeEditar = ehPrevista;
            const podeAlternar = ehPrevista || ehCancelada;
            const podeExcluir = ehPrevista || ehCancelada;

            return (
              <TableRow key={r.id}>
                <TableCell className="font-mono text-xs">{formatDataBR(r.dataPrevista)}</TableCell>
                <TableCell>
                  <div className="font-medium">{r.cliente.nome}</div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {r.processo.numeroCnj ? formatCnj(r.processo.numeroCnj) : "— sem CNJ —"}
                  </div>
                </TableCell>
                <TableCell className="text-sm">
                  <div>{TIPO_PARCELA_LABELS[r.tipoParcela]}</div>
                  {r.numeroParcela && r.totalParcelas && (
                    <div className="text-xs text-muted-foreground">
                      {r.numeroParcela}/{r.totalParcelas}
                    </div>
                  )}
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">
                  {toBRL(valorParcela)}
                  {ressarc > 0 && (
                    <div className="text-xs text-muted-foreground">ressarc. {toBRL(ressarc)}</div>
                  )}
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums text-sm">
                  <div>{toBRL(honor)}</div>
                  <div className="text-xs text-muted-foreground">{toPercent(ph)}</div>
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums text-sm font-semibold">
                  {toBRL(valorCliente)}
                </TableCell>
                <TableCell className="text-sm">
                  {r.parceiro ? (
                    <>
                      <div>{r.parceiro.nome}</div>
                      <div className="text-xs text-muted-foreground">
                        {toPercent(r.percParceiro)}
                      </div>
                    </>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </TableCell>
                <TableCell>
                  <Badge variant={statusVariant(r.status)}>
                    {STATUS_RECEBIVEL_LABELS[r.status]}
                  </Badge>
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    {podeEditar && (
                      <RecebivelFormDialog
                        modo="editar"
                        recebivelId={r.id}
                        processos={processos}
                        parceiros={parceiros}
                        initialValues={{
                          processoId: r.processoId,
                          dataPrevista: r.dataPrevista.toISOString().slice(0, 10),
                          tipoParcela: r.tipoParcela,
                          numeroParcela:
                            r.numeroParcela !== null ? String(r.numeroParcela) : undefined,
                          totalParcelas:
                            r.totalParcelas !== null ? String(r.totalParcelas) : undefined,
                          valorIntegral: Number(r.valorIntegral),
                          valorParcela: Number(r.valorParcela),
                          ressarcimentoEmbutido: Number(r.ressarcimentoEmbutido),
                          percHonorarios: r.percHonorarios.mul(100).toString(),
                          parceiroId: r.parceiroId ?? undefined,
                          percParceiro: r.percParceiro
                            ? r.percParceiro.mul(100).toString()
                            : undefined,
                          observacoes: r.observacoes ?? undefined,
                        }}
                      />
                    )}
                    {podeAlternar && (
                      <RecebivelCancelToggle recebivelId={r.id} cancelado={ehCancelada} />
                    )}
                    {podeExcluir && (
                      <RecebivelDeleteDialog
                        recebivelId={r.id}
                        rotulo={`${r.cliente.nome} · ${toBRL(valorParcela)}`}
                        podeExcluir
                      />
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

function statusVariant(s: StatusRecebivel) {
  switch (s) {
    case "PREVISTA":
      return "outline" as const;
    case "RECEBIDA":
      return "success" as const;
    case "REPASSADA":
      return "default" as const;
    case "CANCELADA":
      return "muted" as const;
  }
}
