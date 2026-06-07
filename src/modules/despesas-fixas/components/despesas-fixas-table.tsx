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

import { DespesaFixaFormDialog } from "./despesa-fixa-form-dialog";
import { DespesaFixaDeleteDialog } from "./despesa-fixa-delete-dialog";
import type { CategoriaDespesaOpcao, ContaOpcao, DespesaFixaComRelacoes } from "../queries";

type Props = {
  despesas: DespesaFixaComRelacoes[];
  categorias: CategoriaDespesaOpcao[];
  contas: ContaOpcao[];
};

export function DespesasFixasTable({ despesas, categorias, contas }: Props) {
  if (despesas.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhuma despesa fixa cadastrada. Comece pelas que se repetem todo mês: luz, condomínio,
        internet, etc.
      </div>
    );
  }

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Nome</TableHead>
            <TableHead>Categoria</TableHead>
            <TableHead>Conta</TableHead>
            <TableHead className="text-right">Valor estimado</TableHead>
            <TableHead className="text-center">Vence dia</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {despesas.map((d) => (
            <TableRow key={d.id}>
              <TableCell className="font-medium">{d.nome}</TableCell>
              <TableCell className="text-sm text-muted-foreground">{d.categoria.nome}</TableCell>
              <TableCell className="text-sm text-muted-foreground">{d.conta.nome}</TableCell>
              <TableCell className="text-right font-mono tabular-nums">
                {toBRL(Number(d.valorEstimado))}
              </TableCell>
              <TableCell className="text-center font-mono text-sm">{d.diaVencimento}</TableCell>
              <TableCell>
                <Badge variant={d.ativo ? "success" : "muted"}>
                  {d.ativo ? "Ativa" : "Inativa"}
                </Badge>
              </TableCell>
              <TableCell>
                <div className="flex items-center justify-end gap-1">
                  <DespesaFixaFormDialog
                    modo="editar"
                    despesaId={d.id}
                    categorias={categorias}
                    contas={contas}
                    initialValues={{
                      nome: d.nome,
                      categoriaId: d.categoriaId,
                      contaId: d.contaId,
                      valorEstimado: Number(d.valorEstimado),
                      diaVencimento: d.diaVencimento,
                      ativo: d.ativo,
                      observacoes: d.observacoes ?? undefined,
                    }}
                  />
                  <DespesaFixaDeleteDialog id={d.id} nome={d.nome} />
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
