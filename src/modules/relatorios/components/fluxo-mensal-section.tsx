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
  fluxo: Array<{ mes: string; entradas: number; saidas: number; saldo: number }>;
};

const MES_NOMES = [
  "Jan",
  "Fev",
  "Mar",
  "Abr",
  "Mai",
  "Jun",
  "Jul",
  "Ago",
  "Set",
  "Out",
  "Nov",
  "Dez",
];

function formatMes(chave: string): string {
  const [ano, mes] = chave.split("-");
  const idx = Number(mes) - 1;
  if (idx < 0 || idx > 11) return chave;
  return `${MES_NOMES[idx]}/${ano.slice(2)}`;
}

export function FluxoMensalSection({ fluxo }: Props) {
  const totais = fluxo.reduce(
    (acc, m) => ({
      entradas: acc.entradas + m.entradas,
      saidas: acc.saidas + m.saidas,
      saldo: acc.saldo + m.saldo,
    }),
    { entradas: 0, saidas: 0, saldo: 0 },
  );

  return (
    <section className="space-y-3">
      <header>
        <h2 className="text-lg font-semibold">Fluxo de caixa mensal</h2>
        <p className="text-xs text-muted-foreground">
          Entradas e saídas agrupadas por mês, excluídas as transferências internas.
        </p>
      </header>

      <div className="rounded-md border bg-card">
        {fluxo.length === 0 ? (
          <div className="px-4 py-6 text-center text-sm text-muted-foreground">
            Nenhum lançamento no período.
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Mês</TableHead>
                <TableHead className="text-right">Entradas</TableHead>
                <TableHead className="text-right">Saídas</TableHead>
                <TableHead className="text-right">Saldo</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {fluxo.map((m) => (
                <TableRow key={m.mes}>
                  <TableCell className="font-medium">{formatMes(m.mes)}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums text-emerald-700">
                    {toBRL(m.entradas)}
                  </TableCell>
                  <TableCell className="text-right font-mono tabular-nums text-destructive">
                    {toBRL(m.saidas)}
                  </TableCell>
                  <TableCell
                    className={`text-right font-mono font-semibold tabular-nums ${
                      m.saldo >= 0 ? "text-emerald-700" : "text-destructive"
                    }`}
                  >
                    {toBRL(m.saldo)}
                  </TableCell>
                </TableRow>
              ))}
              <TableRow>
                <TableCell className="font-medium">Total</TableCell>
                <TableCell className="text-right font-mono font-semibold tabular-nums">
                  {toBRL(totais.entradas)}
                </TableCell>
                <TableCell className="text-right font-mono font-semibold tabular-nums">
                  {toBRL(totais.saidas)}
                </TableCell>
                <TableCell
                  className={`text-right font-mono font-semibold tabular-nums ${
                    totais.saldo >= 0 ? "text-emerald-700" : "text-destructive"
                  }`}
                >
                  {toBRL(totais.saldo)}
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        )}
      </div>
    </section>
  );
}
