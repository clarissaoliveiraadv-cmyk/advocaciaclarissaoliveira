import type { Perfil } from "@prisma/client";
import { signOut } from "@/auth";
import { Button } from "@/components/ui/button";

type HeaderProps = {
  nome: string | null | undefined;
  email: string;
  perfil: Perfil;
};

export function Header({ nome, email, perfil }: HeaderProps) {
  return (
    <header className="flex items-center justify-between border-b bg-background px-6 py-3 print:hidden">
      <div className="text-sm text-muted-foreground">
        Bem-vinda, <span className="font-medium text-foreground">{nome ?? email}</span>
        <span className="ml-2 rounded-full bg-muted px-2 py-0.5 text-xs">{perfil}</span>
      </div>
      <form
        action={async () => {
          "use server";
          await signOut({ redirectTo: "/login" });
        }}
      >
        <Button type="submit" variant="ghost" size="sm">
          Sair
        </Button>
      </form>
    </header>
  );
}
