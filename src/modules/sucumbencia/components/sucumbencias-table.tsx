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
  MarcarRepasseParceiroDialog,
  ReverterRepasseParceiroButton,
} from "./sucumbencia-row-actions";
import { calcularDistribuicaoSucumbencia } from "../schema";
import type {
  CategoriaReceitaOpcao,
  ContaOpcao,
  ParceiroOpcao,
  ProcessoOpcao,
  SucumbenciaComRelacoes,
} from "../queries";

type Props = {
  sucumbencias: SucumbenciaComRelacoes[];
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
  contas: ContaOpcao[];
  categoriasReceita: CategoriaReceitaOpcao[];
};

export function SucumbenciasTable({
  sucumbencias,
  processos,
  parceiros,
  contas,
  categoriasReceita,
}: Props) {
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
            <TableHead>Conta</TableHead>
            <TableHead className="text-right">Bruto</TableHead>
            <TableHead className="text-right">Escritório</TableHead>
            <TableHead>Parceiro externo</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sucumbencias.map((s) => {
            const dist = calcularDistribuicaoSucumbencia({
              valorTotal: Number(s.valorTotal),
              percParceiroExterno: s.percParceiroExterno ? Number(s.percParceiroExterno) : 0,
            });
            const temParceiro = !!s.parceiroExternoId;
            const ehParceiroPago = !!s.dataRepasseParceiroExterno;

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
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {s.contaRecebimento.nome}
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">
                  {toBRL(Number(s.valorTotal))}
                </TableCell>
                <TableCell className="text-right font-mono font-semibold tabular-nums text-emerald-700">
                  {toBRL(dist.escritorio)}
                </TableCell>
                <TableCell className="text-sm">
                  {temParceiro && s.parceiroExterno ? (
                    <div className="space-y-0.5">
                      <div>{s.parceiroExterno.nome}</div>
                      <div className="font-mono text-xs text-muted-foreground">
                        {toBRL(dist.parceiroExterno)}
                      </div>
                      {ehParceiroPago ? (
                        <Badge variant="success" className="text-[10px]">
                          Pago em {formatDataBR(s.dataRepasseParceiroExterno!)}
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-[10px]">
                          Pendente
                        </Badge>
                      )}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    {temParceiro &&
                      (ehParceiroPago ? (
                        <ReverterRepasseParceiroButton id={s.id} />
                      ) : (
                        <MarcarRepasseParceiroDialog id={s.id} />
                      ))}
                    <SucumbenciaFormDialog
                      modo="editar"
                      sucumbenciaId={s.id}
                      processos={processos}
                      parceiros={parceiros}
                      contas={contas}
                      categoriasReceita={categoriasReceita}
                      initialValues={{
                        processoId: s.processoId,
                        valorTotal: Number(s.valorTotal),
                        dataRecebimento: s.dataRecebimento.toISOString().slice(0, 10),
                        contaRecebimentoId: s.contaRecebimentoId,
                        categoriaLancamentoId: s.categoriaLancamentoId,
                        descricaoLancamento:
                          s.lancamentoEntrada?.descricao ?? `Sucumbência — ${s.cliente.nome}`,
                        parceiroExternoId: s.parceiroExternoId ?? undefined,
                        percParceiroExterno: s.percParceiroExterno
                          ? s.percParceiroExterno.mul(100).toString()
                          : undefined,
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
