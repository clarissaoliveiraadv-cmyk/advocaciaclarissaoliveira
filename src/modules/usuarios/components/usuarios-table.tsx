import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { formatDataBR } from "@/lib/datas";

import { PERFIL_LABELS } from "../schema";
import { UsuarioEditDialog } from "./usuario-edit-dialog";
import { ResetSenhaDialog } from "./reset-senha-dialog";
import type { UsuarioListado } from "../queries";

type Props = { usuarios: UsuarioListado[]; usuarioAtualId: string };

export function UsuariosTable({ usuarios, usuarioAtualId }: Props) {
  if (usuarios.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
        Nenhum usuário cadastrado.
      </div>
    );
  }

  return (
    <div className="rounded-md border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Nome / e-mail</TableHead>
            <TableHead>Perfil</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="w-[180px]">Cadastrado em</TableHead>
            <TableHead className="text-right">Ações</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {usuarios.map((u) => (
            <TableRow key={u.id}>
              <TableCell>
                <div className="font-medium">
                  {u.nome}
                  {u.id === usuarioAtualId && (
                    <Badge variant="secondary" className="ml-2 text-[10px]">
                      você
                    </Badge>
                  )}
                </div>
                <div className="text-xs text-muted-foreground">{u.email}</div>
              </TableCell>
              <TableCell className="text-sm">{PERFIL_LABELS[u.perfil]}</TableCell>
              <TableCell>
                <Badge variant={u.ativo ? "success" : "muted"}>
                  {u.ativo ? "Ativo" : "Inativo"}
                </Badge>
              </TableCell>
              <TableCell className="font-mono text-xs">{formatDataBR(u.criadoEm)}</TableCell>
              <TableCell>
                <div className="flex items-center justify-end gap-1">
                  <UsuarioEditDialog
                    usuarioId={u.id}
                    initialValues={{ nome: u.nome, perfil: u.perfil, ativo: u.ativo }}
                  />
                  <ResetSenhaDialog usuarioId={u.id} email={u.email} />
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
