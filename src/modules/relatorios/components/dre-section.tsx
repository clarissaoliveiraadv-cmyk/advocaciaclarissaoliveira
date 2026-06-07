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
  receitas: { categoria: string; valor: number }[];
  despesas: { categoria: string; valor: number }[];
  totalReceitas: number;
  totalDespesas: number;
  resultado: number;
};

export function DreSection({
  receitas,
  despesas,
  totalReceitas,
  totalDespesas,
  resultado,
}: Props) {
  return (
    <section className="space-y-3">
      <header>
        <h2 className="text-lg font-semibold">DRE simplificado</h2>
        <p className="text-xs text-muted-foreground">
          Demonstrativo de resultado por categoria. Transferências entre contas são excluídas.
        </p>
      </header>

      <div className="grid gap-4 lg:grid-cols-2">
        <ColunaCategoria
          titulo="Receitas"
          itens={receitas}
          total={totalReceitas}
          corTotal="text-emerald-700"
        />
        <ColunaCategoria
          titulo="Despesas"
          itens={despesas}
          total={totalDespesas}
          corTotal="text-destructive"
        />
      </div>

      <div className="flex items-center justify-between rounded-md border bg-card p-4">
        <span className="font-medium">Resultado do período</span>
        <span
          className={`font-mono text-xl font-semibold tabular-nums ${
            resultado >= 0 ? "text-emerald-700" : "text-destructive"
          }`}
        >
          {toBRL(resultado)}
        </span>
      </div>
    </section>
  );
}

function ColunaCategoria({
  titulo,
  itens,
  total,
  corTotal,
}: {
  titulo: string;
  itens: { categoria: string; valor: number }[];
  total: number;
  corTotal: string;
}) {
  return (
    <div className="rounded-md border bg-card">
      <div className="border-b px-4 py-2 text-sm font-medium">{titulo}</div>
      {itens.length === 0 ? (
        <div className="px-4 py-6 text-center text-sm text-muted-foreground">
          Nenhum lançamento no período.
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Categoria</TableHead>
              <TableHead className="text-right">Valor</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {itens.map((i) => (
              <TableRow key={i.categoria}>
                <TableCell>{i.categoria}</TableCell>
                <TableCell className="text-right font-mono tabular-nums">{toBRL(i.valor)}</TableCell>
              </TableRow>
            ))}
            <TableRow>
              <TableCell className="font-medium">Total</TableCell>
              <TableCell
                className={`text-right font-mono font-semibold tabular-nums ${corTotal}`}
              >
                {toBRL(total)}
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )}
    </div>
  );
}
