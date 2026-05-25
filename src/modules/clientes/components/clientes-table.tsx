import type { Cliente } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { formatCpfCnpj, formatTelefone } from "@/lib/format";

import { ClienteFormDialog } from "./cliente-form-dialog";
import { ClienteDeleteDialog } from "./cliente-delete-dialog";
import { ClienteAtivoToggle } from "./cliente-row-actions";

type Props = { clientes: Cliente[] };

export async function ClientesTable({ clientes }: Props) {
  if (clientes.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhum cliente encontrado.
      </div>
    );
  }

  const dependencias = await contarDependencias(clientes.map((c) => c.id));

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Nome</TableHead>
            <TableHead>CPF/CNPJ</TableHead>
            <TableHead>Contato</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {clientes.map((c) => (
            <TableRow key={c.id}>
              <TableCell className="font-medium">{c.nome}</TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {c.cpfCnpj ? formatCpfCnpj(c.cpfCnpj) : "—"}
              </TableCell>
              <TableCell className="text-sm">
                <div>{c.email ?? "—"}</div>
                <div className="text-xs text-muted-foreground">
                  {c.telefone ? formatTelefone(c.telefone) : "—"}
                </div>
              </TableCell>
              <TableCell>
                <Badge variant={c.ativo ? "success" : "muted"}>
                  {c.ativo ? "Ativo" : "Inativo"}
                </Badge>
              </TableCell>
              <TableCell>
                <div className="flex items-center justify-end gap-1">
                  <ClienteFormDialog
                    modo="editar"
                    clienteId={c.id}
                    initialValues={{
                      nome: c.nome,
                      cpfCnpj: c.cpfCnpj ?? undefined,
                      email: c.email ?? undefined,
                      telefone: c.telefone ?? undefined,
                      observacoes: c.observacoes ?? undefined,
                    }}
                  />
                  <ClienteAtivoToggle clienteId={c.id} ativo={c.ativo} />
                  <ClienteDeleteDialog
                    clienteId={c.id}
                    clienteNome={c.nome}
                    podeExcluir={!dependencias.has(c.id)}
                  />
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

async function contarDependencias(ids: string[]): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const [processos, recebiveis, lancamentos, ressarcimentos] = await Promise.all([
    prisma.processo.groupBy({ by: ["clienteId"], where: { clienteId: { in: ids } }, _count: true }),
    prisma.recebivel.groupBy({
      by: ["clienteId"],
      where: { clienteId: { in: ids } },
      _count: true,
    }),
    prisma.lancamento.groupBy({
      by: ["clienteId"],
      where: { clienteId: { in: ids } },
      _count: true,
    }),
    prisma.ressarcimento.groupBy({
      by: ["clienteId"],
      where: { clienteId: { in: ids } },
      _count: true,
    }),
  ]);
  const set = new Set<string>();
  for (const g of [...processos, ...recebiveis, ...lancamentos, ...ressarcimentos]) {
    if (g.clienteId) set.add(g.clienteId);
  }
  return set;
}
