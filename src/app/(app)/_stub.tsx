export function Stub({ title, descricao }: { title: string; descricao: string }) {
  return (
    <div className="space-y-3">
      <h1 className="text-2xl font-semibold">{title}</h1>
      <p className="text-sm text-slate-500">{descricao}</p>
      <div className="rounded-xl border border-dashed bg-white p-8 text-center text-sm text-slate-500">
        Módulo em construção. Schema Prisma já está pronto — basta implementar CRUD + UI.
      </div>
    </div>
  );
}
