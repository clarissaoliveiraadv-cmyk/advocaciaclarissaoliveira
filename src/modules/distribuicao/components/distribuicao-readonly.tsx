import { CheckCircle2 } from "lucide-react";

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

import { TIPO_BENEFICIARIO_LABELS } from "../schema";
import type { DistribuicaoCompleta } from "../queries";

type Props = { distribuicao: DistribuicaoCompleta };

export function DistribuicaoReadonly({ distribuicao }: Props) {
  const total = distribuicao.itens.reduce((acc, i) => acc + Number(i.valor), 0);
  const repassados = distribuicao.itens.filter((i) => i.status === "REPASSADO").length;
  const pendentes = distribuicao.itens.filter((i) => i.status === "PENDENTE_REPASSE").length;

  return (
    <div className="space-y-4">
      <section className="rounded-md border bg-card p-4">
        <div className="flex items-center gap-2 text-sm">
          <CheckCircle2 className="h-5 w-5 text-emerald-700" />
          <span className="font-medium">Distribuição confirmada</span>
          <Badge variant="success" className="ml-2">
            {distribuicao.status}
          </Badge>
        </div>
        <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-sm sm:grid-cols-3">
          <dt className="text-muted-foreground">Data do recebimento</dt>
          <dd className="font-mono sm:col-span-2">{formatDataBR(distribuicao.dataRecebimento)}</dd>
          <dt className="text-muted-foreground">Valor bruto</dt>
          <dd className="font-mono tabular-nums sm:col-span-2">
            {toBRL(Number(distribuicao.valorBrutoRecebido))}
          </dd>
          <dt className="text-muted-foreground">Itens</dt>
          <dd className="sm:col-span-2">
            {distribuicao.itens.length} ({repassados} repassados, {pendentes} pendentes)
          </dd>
          {distribuicao.observacoes && (
            <>
              <dt className="text-muted-foreground">Observações</dt>
              <dd className="sm:col-span-2">{distribuicao.observacoes}</dd>
            </>
          )}
        </dl>
      </section>

      <div className="rounded-md border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Beneficiário</TableHead>
              <TableHead>Descrição</TableHead>
              <TableHead>Vínculo</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Valor</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {distribuicao.itens.map((i) => (
              <TableRow key={i.id}>
                <TableCell>
                  <Badge variant="outline">{TIPO_BENEFICIARIO_LABELS[i.beneficiario]}</Badge>
                </TableCell>
                <TableCell className="text-sm">{i.descricao ?? "—"}</TableCell>
                <TableCell className="text-sm">
                  {i.cliente?.nome ?? i.parceiro?.nome ?? "—"}
                </TableCell>
                <TableCell>
                  <Badge variant={i.status === "REPASSADO" ? "success" : "muted"}>
                    {i.status === "REPASSADO"
                      ? "Repassado"
                      : i.status === "PENDENTE_REPASSE"
                        ? "Pendente"
                        : "Em custódia"}
                  </Badge>
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">
                  {toBRL(Number(i.valor))}
                </TableCell>
              </TableRow>
            ))}
            <TableRow>
              <TableCell colSpan={4} className="text-right text-sm font-medium">
                Total
              </TableCell>
              <TableCell className="text-right font-mono font-semibold tabular-nums">
                {toBRL(total)}
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
