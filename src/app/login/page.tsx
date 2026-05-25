import { LoginForm } from "./login-form";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ erro?: string }>;
}) {
  const { erro } = await searchParams;

  return (
    <main className="flex min-h-screen items-center justify-center bg-muted p-4">
      <div className="w-full max-w-sm rounded-xl border bg-card p-8 shadow-sm">
        <h1 className="mb-1 text-2xl font-semibold text-primary">Advocacia Clarissa Oliveira</h1>
        <p className="mb-6 text-sm text-muted-foreground">Gestão Financeira</p>
        <LoginForm erro={Boolean(erro)} />
      </div>
    </main>
  );
}
