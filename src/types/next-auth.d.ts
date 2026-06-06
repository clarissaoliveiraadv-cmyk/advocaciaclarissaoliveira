import type { Perfil } from "@prisma/client";
import "next-auth";
import "next-auth/jwt";

declare module "next-auth" {
  interface User {
    perfil?: Perfil;
  }
  interface Session {
    user: {
      id: string;
      email: string;
      name?: string | null;
      perfil: Perfil;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    uid?: string;
    perfil?: Perfil;
  }
}
