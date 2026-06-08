import { requirePerfil, PERFIS_ADMIN } from "@/lib/auth/guards";
import { listUsuarios } from "@/modules/usuarios/queries";
import { UsuariosTable } from "@/modules/usuarios/components/usuarios-table";
import { UsuarioFormDialog } from "@/modules/usuarios/components/usuario-form-dialog";

export const dynamic = "force-dynamic";

export default async function UsuariosPage() {
  const session = await requirePerfil(PERFIS_ADMIN);
  const usuarios = await listUsuarios();

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Usuários</h1>
          <p className="text-sm text-muted-foreground">
            Quem pode acessar o sistema. Crie um usuário para cada pessoa (financeiro, secretária,
            parceiro) com o perfil adequado — ela faz login com o próprio e-mail e a senha que você
            definir.
          </p>
        </div>
        <UsuarioFormDialog />
      </header>

      <UsuariosTable usuarios={usuarios} usuarioAtualId={session.user.id} />
    </div>
  );
}
