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
import { cn } from "@/lib/utils";

import { CategoriaFormDialog } from "./categoria-form-dialog";
import { CategoriaDeleteDialog } from "./categoria-delete-dialog";
import { CategoriaAtivoToggle } from "./categoria-row-actions";
import type { CategoriaArvore, CategoriaOpcao } from "../queries";
import { TIPO_CATEGORIA_LABELS } from "../schema";

type Props = { categorias: CategoriaArvore[]; opcoes: CategoriaOpcao[] };

export async function CategoriasTable({ categorias, opcoes }: Props) {
  if (categorias.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhuma categoria encontrada.
      </div>
    );
  }

  const dependencias = await contarDependencias(categorias.map((c) => c.id));

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Nome</TableHead>
            <TableHead>Tipo</TableHead>
            <TableHead>Escopo</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {categorias.map((c) => {
            const deps = dependencias.get(c.id) ?? { lanc: 0, filhas: 0 };
            const podeExcluir = deps.lanc === 0 && deps.filhas === 0;
            const motivos: string[] = [];
            if (deps.lanc > 0) motivos.push(`${deps.lanc} lançamento(s)`);
            if (deps.filhas > 0) motivos.push(`${deps.filhas} subcategoria(s)`);
            const motivoBloqueio =
              motivos.length > 0
                ? `Possui ${motivos.join(" e ")} vinculados. Inative em vez de excluir.`
                : undefined;

            return (
              <TableRow key={c.id}>
                <TableCell>
                  <div className={cn("flex items-center", c.profundidade > 0 && "text-sm")}>
                    {c.profundidade > 0 && (
                      <span
                        className="mr-2 inline-block text-muted-foreground"
                        style={{ paddingLeft: `${(c.profundidade - 1) * 16}px` }}
                        aria-hidden
                      >
                        ↳
                      </span>
                    )}
                    <span className={cn(c.profundidade === 0 ? "font-medium" : "")}>{c.nome}</span>
                  </div>
                  {c.categoriaPai && c.profundidade === 0 && (
                    <div className="text-xs text-muted-foreground">sob {c.categoriaPai.nome}</div>
                  )}
                </TableCell>
                <TableCell>
                  <Badge variant={c.tipo === "RECEITA" ? "success" : "secondary"}>
                    {TIPO_CATEGORIA_LABELS[c.tipo]}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={c.isPessoal ? "outline" : "muted"}>
                    {c.isPessoal ? "Pessoal" : "Escritório"}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={c.ativo ? "success" : "muted"}>
                    {c.ativo ? "Ativa" : "Inativa"}
                  </Badge>
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    <CategoriaFormDialog
                      modo="editar"
                      categoriaId={c.id}
                      categorias={opcoes}
                      temFilhas={deps.filhas > 0}
                      initialValues={{
                        nome: c.nome,
                        tipo: c.tipo,
                        isPessoal: c.isPessoal,
                        categoriaPaiId: c.categoriaPaiId ?? undefined,
                      }}
                    />
                    <CategoriaAtivoToggle categoriaId={c.id} ativo={c.ativo} />
                    <CategoriaDeleteDialog
                      categoriaId={c.id}
                      rotulo={c.nome}
                      podeExcluir={podeExcluir}
                      motivoBloqueio={motivoBloqueio}
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

async function contarDependencias(
  ids: string[],
): Promise<Map<string, { lanc: number; filhas: number }>> {
  const result = new Map<string, { lanc: number; filhas: number }>();
  if (ids.length === 0) return result;

  const [lanc, filhas] = await Promise.all([
    prisma.lancamento.groupBy({
      by: ["categoriaId"],
      where: { categoriaId: { in: ids } },
      _count: true,
    }),
    prisma.categoria.groupBy({
      by: ["categoriaPaiId"],
      where: { categoriaPaiId: { in: ids } },
      _count: true,
    }),
  ]);

  for (const id of ids) result.set(id, { lanc: 0, filhas: 0 });
  for (const g of lanc) {
    const cur = result.get(g.categoriaId);
    if (cur) cur.lanc = g._count;
  }
  for (const g of filhas) {
    if (!g.categoriaPaiId) continue;
    const cur = result.get(g.categoriaPaiId);
    if (cur) cur.filhas = g._count;
  }
  return result;
}
