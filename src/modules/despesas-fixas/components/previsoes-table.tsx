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

import { MarcarPagaDialog } from "./marcar-paga-dialog";
import { PularPrevisaoButton, ReverterPagamentoButton } from "./previsao-row-actions";
import type { ContaOpcao, PrevisaoComRelacoes } from "../queries";

type Props = {
  previsoes: PrevisaoComRelacoes[];
  contas: ContaOpcao[];
};

export function PrevisoesTable({ previsoes, contas }: Props) {
  if (previsoes.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhuma previsão para este mês. Use &quot;Gerar previsões deste mês&quot; se já cadastrou
        suas despesas fixas.
      </div>
    );
  }

  const hoje = new Date();
  const hojeISO = hoje.toISOString().slice(0, 10);

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Vence</TableHead>
            <TableHead>Despesa</TableHead>
            <TableHead>Categoria</TableHead>
            <TableHead>Conta</TableHead>
            <TableHead className="text-right">Valor previsto</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {previsoes.map((p) => {
            const venceISO = p.dataVencimento.toISOString().slice(0, 10);
            const vencida = !p.lancamentoId && venceISO < hojeISO;
            const paga = !!p.lancamentoId;

            return (
              <TableRow key={p.id}>
                <TableCell className="font-mono text-xs">
                  <div>{formatDataBR(p.dataVencimento)}</div>
                  {vencida && (
                    <div className="text-[10px] font-semibold text-destructive">vencida</div>
                  )}
                </TableCell>
                <TableCell className="font-medium">{p.despesaFixa.nome}</TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {p.despesaFixa.categoria.nome}
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {p.despesaFixa.conta.nome}
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">
                  {toBRL(Number(p.valorPrevisto))}
                </TableCell>
                <TableCell>
                  {paga ? (
                    <div className="space-y-0.5">
                      <Badge variant="success">Paga</Badge>
                      <div className="font-mono text-xs text-muted-foreground">
                        {p.dataPagamento && formatDataBR(p.dataPagamento)}
                      </div>
                    </div>
                  ) : vencida ? (
                    <Badge variant="destructive">Vencida</Badge>
                  ) : (
                    <Badge variant="outline">Pendente</Badge>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    {paga ? (
                      <ReverterPagamentoButton id={p.id} />
                    ) : (
                      <>
                        <MarcarPagaDialog
                          previsaoId={p.id}
                          nomeDespesa={p.despesaFixa.nome}
                          valorPrevisto={Number(p.valorPrevisto)}
                          contaPadraoId={p.despesaFixa.contaId}
                          contas={contas}
                        />
                        <PularPrevisaoButton id={p.id} />
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
