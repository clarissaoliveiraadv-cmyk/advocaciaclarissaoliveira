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

import { ParceriaFormDialog } from "./parceria-form-dialog";
import { ParceriaDeleteDialog } from "./parceria-delete-dialog";
import {
  MarcarParceriaPagaDialog,
  ReverterParceriaPagaButton,
} from "./parceria-row-actions";
import { calcularDevidoAoParceiro } from "../schema";
import type { ParceiroOpcao, ParceriaComRelacoes, ProcessoOpcao } from "../queries";

type Props = {
  parcerias: ParceriaComRelacoes[];
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
};

export function ParceriasTable({ parcerias, processos, parceiros }: Props) {
  if (parcerias.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhuma parceria encontrada no período/filtro selecionado.
      </div>
    );
  }

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Acordo</TableHead>
            <TableHead>Parceiro / Processo</TableHead>
            <TableHead className="text-right">Total</TableHead>
            <TableHead className="text-right">Recebido</TableHead>
            <TableHead className="text-right">Devido</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {parcerias.map((p) => {
            const devido = calcularDevidoAoParceiro({
              valorRecebido: Number(p.valorRecebido),
              percHonorarios: Number(p.percHonorarios),
              ressarcimentos: Number(p.ressarcimentos),
              percParceiro: Number(p.percParceiro),
            });
            const ehPaga = !!p.dataPgto;

            return (
              <TableRow key={p.id}>
                <TableCell className="font-mono text-xs">{formatDataBR(p.dataAcordo)}</TableCell>
                <TableCell>
                  <div className="font-medium">{p.parceiro.nome}</div>
                  <div className="text-xs text-muted-foreground">
                    {p.cliente.nome}
                    {" · "}
                    <span className="font-mono">
                      {p.processo.numeroCnj ? formatCnj(p.processo.numeroCnj) : "— sem CNJ —"}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">
                  {toBRL(Number(p.valorTotal))}
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums text-sm">
                  <div>{toBRL(Number(p.valorRecebido))}</div>
                  <div className="text-xs text-muted-foreground">
                    {toPercent(p.percHonorarios)} honor.
                  </div>
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">
                  <div className="font-semibold text-amber-700">{toBRL(devido)}</div>
                  <div className="text-xs text-muted-foreground">{toPercent(p.percParceiro)}</div>
                </TableCell>
                <TableCell>
                  {ehPaga ? (
                    <div className="space-y-0.5">
                      <Badge variant="success">Paga</Badge>
                      <div className="font-mono text-xs text-muted-foreground">
                        {p.dataPgto && formatDataBR(p.dataPgto)}
                      </div>
                    </div>
                  ) : (
                    <Badge variant="outline">Pendente</Badge>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    {ehPaga ? (
                      <ReverterParceriaPagaButton id={p.id} />
                    ) : (
                      <MarcarParceriaPagaDialog id={p.id} />
                    )}
                    <ParceriaFormDialog
                      modo="editar"
                      parceriaId={p.id}
                      processos={processos}
                      parceiros={parceiros}
                      initialValues={{
                        parceiroId: p.parceiroId,
                        processoId: p.processoId,
                        dataAcordo: p.dataAcordo.toISOString().slice(0, 10),
                        valorTotal: Number(p.valorTotal),
                        valorRecebido: Number(p.valorRecebido),
                        percHonorarios: p.percHonorarios.mul(100).toString(),
                        ressarcimentos: Number(p.ressarcimentos),
                        percParceiro: p.percParceiro.mul(100).toString(),
                        dataPgto: p.dataPgto ? p.dataPgto.toISOString().slice(0, 10) : undefined,
                        observacoes: p.observacoes ?? undefined,
                      }}
                    />
                    <ParceriaDeleteDialog
                      id={p.id}
                      rotulo={`${p.parceiro.nome} · ${p.cliente.nome}`}
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
