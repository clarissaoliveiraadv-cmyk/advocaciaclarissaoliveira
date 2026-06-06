import { requireAuth } from "@/lib/auth/guards";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { Toaster } from "@/components/ui/sonner";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await requireAuth();

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Header nome={session.user.name} email={session.user.email} perfil={session.user.perfil} />
        <main className="flex-1 p-6">{children}</main>
      </div>
      <Toaster />
    </div>
  );
}
