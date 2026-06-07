import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { toBRL } from "@/lib/money";

type Props = {
  itens: Array<{
    clienteId: string;
    nome: string;
    bruto: number;
    repassado: number;
    custodia: number;
    pendente: number;
    ressarcAReceber: number;
  }>;
};

export function PorClienteSection({ itens }: Props) {
  return (
    <section className="space-y-3">
      <header>
        <h2 className="text-lg font-semibold">Posição por cliente</h2>
        <p className="text-xs text-muted-foreground">
          Quanto recebemos, repassamos, mantemos em custódia, devemos repassar e quanto há de
          ressarcimento a receber, por cliente, no período.
        </p>
      </header>

      <div className="rounded-md border bg-card">
        {itens.length === 0 ? (
          <div className="px-4 py-6 text-center text-sm text-muted-foreground">
            Nenhuma movimentação de cliente no período.
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Cliente</TableHead>
                <TableHead className="text-right">Bruto recebido</TableHead>
                <TableHead className="text-right">Repassado</TableHead>
                <TableHead className="text-right">Em custódia</TableHead>
                <TableHead className="text-right">Pendente</TableHead>
                <TableHead className="text-right">Ressarc. a receber</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {itens.map((i) => (
                <TableRow key={i.clienteId}>
                  <TableCell className="font-medium">{i.nome}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums">
                    {toBRL(i.bruto)}
                  </TableCell>
                  <TableCell className="text-right font-mono tabular-nums text-emerald-700">
                    {toBRL(i.repassado)}
                  </TableCell>
                  <TableCell className="text-right font-mono tabular-nums">
                    {toBRL(i.custodia)}
                  </TableCell>
                  <TableCell className="text-right font-mono tabular-nums text-amber-700">
                    {toBRL(i.pendente)}
                  </TableCell>
                  <TableCell className="text-right font-mono tabular-nums text-amber-700">
                    {toBRL(i.ressarcAReceber)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </section>
  );
}
