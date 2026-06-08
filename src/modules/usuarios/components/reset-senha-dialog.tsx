"use client";

import { useState, useTransition } from "react";
import { Key } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

import { resetSenhaUsuario } from "../actions";

type Props = { usuarioId: string; email: string };

export function ResetSenhaDialog({ usuarioId, email }: Props) {
  const [open, setOpen] = useState(false);
  const [senha, setSenha] = useState("");
  const [pending, startTransition] = useTransition();

  function onConfirm() {
    if (senha.length < 6) {
      toast.error("Senha deve ter ao menos 6 caracteres.");
      return;
    }
    startTransition(async () => {
      const result = await resetSenhaUsuario({ id: usuarioId, senha });
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(`Senha redefinida para ${email}. Compartilhe com a pessoa.`);
      setSenha("");
      setOpen(false);
    });
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm">
          <Key className="mr-1 h-4 w-4" />
          Redefinir senha
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Redefinir senha de {email}</DialogTitle>
          <DialogDescription>
            Defina uma nova senha. A pessoa precisará usar essa senha no próximo login.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <label className="text-sm font-medium">Nova senha (mínimo 6 caracteres)</label>
          <Input
            type="text"
            autoComplete="off"
            value={senha}
            onChange={(e) => setSenha(e.target.value)}
          />
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => {
              setSenha("");
              setOpen(false);
            }}
            disabled={pending}
          >
            Cancelar
          </Button>
          <Button onClick={onConfirm} disabled={pending || senha.length < 6}>
            {pending ? "Salvando..." : "Confirmar"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
