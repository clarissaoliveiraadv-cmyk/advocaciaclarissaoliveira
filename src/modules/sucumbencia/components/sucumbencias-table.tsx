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

import { SucumbenciaFormDialog } from "./sucumbencia-form-dialog";
import { SucumbenciaDeleteDialog } from "./sucumbencia-delete-dialog";
import {
  MarcarRepasseDialog,
  ReverterRepasseButton,
} from "./sucumbencia-row-actions";
import { calcularDistribuicaoSucumbencia } from "../schema";
import type { ParceiroOpcao, ProcessoOpcao, SucumbenciaComRelacoes } from "../queries";

type Props = {
  sucumbencias: SucumbenciaComRelacoes[];
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
};

export function SucumbenciasTable({ sucumbencias, processos, parceiros }: Props) {
  if (sucumbencias.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhuma sucumbência encontrada no período/filtro selecionado.
      </div>
    );
  }

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Recebim.</TableHead>
            <TableHead>Cliente / Processo</TableHead>
            <TableHead className="text-right">Bruto</TableHead>
            <TableHead className="text-right">Escritório</TableHead>
            <TableHead className="text-right">Clarissa</TableHead>
            <TableHead className="text-right">Vivian</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sucumbencias.map((s) => {
            const dist = calcularDistribuicaoSucumbencia({
              valorTotal: Number(s.valorTotal),
              percParceiroExterno: s.percParceiroExterno ? Number(s.percParceiroExterno) : 0,
              percEscritorio: Number(s.percEscritorio),
              percClarissa: Number(s.percClarissa),
              percVivian: Number(s.percVivian),
            });
            return (
              <TableRow key={s.id}>
                <TableCell className="font-mono text-xs">
                  {formatDataBR(s.dataRecebimento)}
                </TableCell>
                <TableCell>
                  <div className="font-medium">{s.cliente.nome}</div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {s.processo.numeroCnj ? formatCnj(s.processo.numeroCnj) : "— sem CNJ —"}
                  </div>
                  {s.parceiroExterno && (
                    <div className="mt-1 text-xs text-muted-foreground">
                      Parceiro externo: {s.parceiroExterno.nome} ({toBRL(dist.parceiroExterno)})
                    </div>
                  )}
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">
                  {toBRL(Number(s.valorTotal))}
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums text-emerald-700">
                  {toBRL(dist.escritorio)}
                </TableCell>
                <TableCell className="text-right">
                  <SociaRepasseCelula
                    id={s.id}
                    socia="clarissa"
                    valor={dist.clarissa}
                    dataRepasse={s.dataRepasseClarissa}
                  />
                </TableCell>
                <TableCell className="text-right">
                  <SociaRepasseCelula
                    id={s.id}
                    socia="vivian"
                    valor={dist.vivian}
                    dataRepasse={s.dataRepasseVivian}
                  />
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    <SucumbenciaFormDialog
                      modo="editar"
                      sucumbenciaId={s.id}
                      processos={processos}
                      parceiros={parceiros}
                      initialValues={{
                        processoId: s.processoId,
                        valorTotal: Number(s.valorTotal),
                        dataRecebimento: s.dataRecebimento.toISOString().slice(0, 10),
                        parceiroExternoId: s.parceiroExternoId ?? undefined,
                        percParceiroExterno: s.percParceiroExterno
                          ? s.percParceiroExterno.mul(100).toString()
                          : undefined,
                        percEscritorio: s.percEscritorio.mul(100).toString(),
                        percClarissa: s.percClarissa.mul(100).toString(),
                        percVivian: s.percVivian.mul(100).toString(),
                        observacoes: s.observacoes ?? undefined,
                      }}
                    />
                    <SucumbenciaDeleteDialog
                      id={s.id}
                      rotulo={`${s.cliente.nome} · ${toBRL(Number(s.valorTotal))}`}
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

function SociaRepasseCelula({
  id,
  socia,
  valor,
  dataRepasse,
}: {
  id: string;
  socia: "clarissa" | "vivian";
  valor: number;
  dataRepasse: Date | null;
}) {
  return (
    <div className="flex flex-col items-end gap-1">
      <span className="font-mono tabular-nums">{toBRL(valor)}</span>
      {dataRepasse ? (
        <div className="flex items-center gap-1">
          <Badge variant="success" className="px-1 py-0 text-[10px]">
            {formatDataBR(dataRepasse)}
          </Badge>
          <ReverterRepasseButton id={id} socia={socia} />
        </div>
      ) : (
        <MarcarRepasseDialog id={id} socia={socia} />
      )}
    </div>
  );
}
