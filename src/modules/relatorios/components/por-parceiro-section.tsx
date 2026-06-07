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
    parceiroId: string;
    nome: string;
    devidoParcerias: number;
    pagoParcerias: number;
    repassadoDistribuicao: number;
    pendenteDistribuicao: number;
  }>;
};

export function PorParceiroSection({ itens }: Props) {
  return (
    <section className="space-y-3">
      <header>
        <h2 className="text-lg font-semibold">Demonstrativo por parceiro</h2>
        <p className="text-xs text-muted-foreground">
          Inclui parcerias acordadas (devido vs pago) e itens de distribuição direta para
          parceiros, no período.
        </p>
      </header>

      <div className="rounded-md border bg-card">
        {itens.length === 0 ? (
          <div className="px-4 py-6 text-center text-sm text-muted-foreground">
            Nenhum parceiro com movimentação no período.
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Parceiro</TableHead>
                <TableHead className="text-right">Devido (parcerias)</TableHead>
                <TableHead className="text-right">Pago (parcerias)</TableHead>
                <TableHead className="text-right">Repassado (distrib.)</TableHead>
                <TableHead className="text-right">Pendente (distrib.)</TableHead>
                <TableHead className="text-right">Saldo a pagar</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {itens.map((i) => {
                const saldo =
                  Math.max(0, i.devidoParcerias - i.pagoParcerias) + i.pendenteDistribuicao;
                return (
                  <TableRow key={i.parceiroId}>
                    <TableCell className="font-medium">{i.nome}</TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {toBRL(i.devidoParcerias)}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums text-emerald-700">
                      {toBRL(i.pagoParcerias)}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums text-emerald-700">
                      {toBRL(i.repassadoDistribuicao)}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums text-amber-700">
                      {toBRL(i.pendenteDistribuicao)}
                    </TableCell>
                    <TableCell className="text-right font-mono font-semibold tabular-nums text-amber-700">
                      {toBRL(saldo)}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </div>
    </section>
  );
}
