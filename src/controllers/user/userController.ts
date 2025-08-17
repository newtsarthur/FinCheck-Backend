import type { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { PrismaClient, Prisma } from '@prisma/client';
import type { User } from '@prisma/client';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();
const JWT_SECRET: string = process.env.JWT_SECRET || 'default_secret';
const { JsonWebTokenError } = jwt;

// Interface para o corpo da requisição de registro
interface RegisterBody {
  email: string;
  name: string;
  password: string;
  phone?: string;
  address?: string;
}

// Interface para o corpo da requisição de login
interface LoginBody {
  email: string;
  password: string;
}

// Interface para o payload do token JWT
interface JwtPayload {
  id: string;
}

// Interface para o corpo da requisição de atualização
interface UpdateUserBody {
  email?: string;
  name?: string;
  password?: string;
  phone?: string;
  address?: string;
}

/**
 * Lida com o registro de um novo usuário.
 *
 * @param req O objeto de requisição do Express com o corpo tipado.
 * @param res O objeto de resposta do Express.
 */
export const register = async (req: Request<{}, {}, RegisterBody>, res: Response) => {
  try {
    const user = req.body;
    const existingUser: User | null = await prisma.user.findUnique({
      where: { email: user.email },
    });

    if (existingUser) {
      return res.status(400).json({ message: "Já existe uma conta com esse email!" });
    }
    if (!user || !user.email || !user.name || !user.password) {
      return res.status(400).json({ message: "Email, nome e senha são obrigatórios!" });
    }
    if(!user.email.includes('@')) {
      return res.status(400).json({ message: "Email inválido!" });
    }

    if(user.password.length < 4) {
      return res.status(400).json({ message: "A senha deve ter pelo menos 4 caracteres!" });
    }

    if(user.phone && user.phone.length < 11) {
      return res.status(400).json({ message: "O telefone deve ter pelo menos 11 dígitos!" });
    }
    if(user.address && user.address.length < 5) {
      return res.status(400).json({ message: "O endereço deve ter pelo menos 5 caracteres!" });
    }
    if(user.phone && !/^\d+$/.test(user.phone)) {
      return res.status(400).json({ message: "O telefone deve conter apenas números!" });
    }
    if(user.phone){
      const existPhone = await prisma.user.findFirst({
        where: { phone: user.phone },
      });

      if (existPhone) {
        return res.status(400).json({ message: "Já existe uma conta com esse número!" });
      }
    }

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(user.password, salt);

    const userDB: User = await prisma.user.create({
      data: {
        email: user.email,
        name: user.name,
        phone: user.phone,
        address: user.address,
        password: hashPassword,
        createdAt: new Date(),
      }
    });

    const token = jwt.sign({ id: userDB.id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      token,
      user: {
        id: userDB.id,
        name: userDB.name,
        email: userDB.email,
        createdAt: userDB.createdAt,
      },
    });
  } catch (error) {
    console.error("Erro ao tentar criar a conta", error);
    const errorMessage = error instanceof Error ? error.message : "Erro desconhecido.";
    res.status(500).json({ message: "Erro no servidor.", error: errorMessage });
  }
};

/**
 * Lida com o login de um usuário existente.
 *
 * @param req O objeto de requisição do Express com o corpo tipado.
 * @param res O objeto de resposta do Express.
 */
export const login = async (req: Request<{}, {}, LoginBody>, res: Response) => {
  try{
    const userInfo = req.body;

    if (!userInfo || !userInfo.email || !userInfo.password) {
      return res.status(400).json({message: "Email e senha são obrigatórios!"});
    }

    const user = await prisma.user.findUnique({
      where: { email: userInfo.email},
    });

    if(!user) {
      return res.status(404).json({message: "Usuário não existe"});
    }
    const isMatch = await bcrypt.compare(userInfo.password, user.password);
    if(!isMatch) {
      return res.status(401).json({message: "Senha incorreta!"});
    }

    const token = jwt.sign({id: user.id}, JWT_SECRET, {expiresIn: '7d'});

    res.status(200).json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    console.error("Erro ao tentar fazer login", error);
    const errorMessage = error instanceof Error ? error.message : "Erro desconhecido.";
    res.status(500).json({ message: "Erro no servidor.", error: errorMessage });
  }
};

/**
 * Lida com a exclusão de um usuário.
 *
 * @param req O objeto de requisição do Express com os parâmetros de rota tipados.
 * @param res O objeto de resposta do Express.
 */
export const deleteUser = async (req: Request<{ id: string}>, res: Response) => {
  try {
    const userId = req.params.id;
    const token = req.headers.authorization?.split(' ')[1];

    if(!token) {
      return res.status(401).json({message: "Token de autenticação não fornecido."});
    }

    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;

    if(decoded.id !== userId) {
      return res.status(403).json({message: "Você não tem permissão para deletar este usuário."});
    }

    const deletedUser = await prisma.user.delete({
      where: {id: userId},
    });

    res.status(200).json({ message: "Usuário deletado com sucesso!", deletedUser });
  } catch (error) {
    if(error instanceof JsonWebTokenError) {
      return res.status(401).json({ message: "Token inválido." });
    }

    if(error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025') {
      return res.status(404).json({ message: "Usuário não encontrado." });
    }

    console.error("Erro ao deletar usuário:", error);
    const errorMessage = error instanceof Error ? error.message : "Erro desconhecido.";
    res.status(500).json({ message: "Erro no servidor.", error: errorMessage });
  }
};

/**
 * Lida com a atualização de um usuário existente.
 *
 * @param req O objeto de requisição do Express com os parâmetros de rota tipados
 * e o corpo da requisição tipado.
 * @param res O objeto de resposta do Express.
 */
export const updateUser = async (req: Request<{ id: string }, {}, UpdateUserBody>, res: Response) => {
  try {
    const userId = req.params.id;
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: "Token de autenticação não foi informado." });
    }

    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    if (decoded.id !== userId) {
      return res.status(403).json({ message: "Você não tem permissão para atualizar este usuário!" });
    }

    const { name, phone, address, email, password } = req.body;

    if (name) {
      if (name.length < 3 || name.length == 0) {
        return res.status(400).json({ message: "O nome deve ter pelo menos 3 letras!" });
      }
    }

    // Verifica se pelo menos um campo foi enviado para atualização
    if (!name && !phone && !address && !email && !password) {
      return res.status(200).json({ message: "Nenhum dado foi alterado." });
    }

    // Busca o usuário atual no banco de dados
    const currentUser = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!currentUser) {
      return res.status(404).json({ message: "Usuário não encontrado." });
    }

    // Inicializa o objeto de atualização
    const updateData: Partial<User> = {};
    let hasChanges = false;

    // Verifica e atualiza cada campo individualmente
    if (name && name !== currentUser.name) {
      updateData.name = name;
      hasChanges = true;
    }

    if (email && email !== currentUser.email) {
      if (!email.includes('@')) {
        return res.status(400).json({ message: "Email inválido!" });
      }

      const existingUser = await prisma.user.findUnique({
        where: { email },
      });

      if (existingUser && existingUser.id !== userId) {
        return res.status(400).json({ message: "Este email já está em uso por outro usuário!" });
      }

      updateData.email = email;
      hasChanges = true;
    }

    if (phone && phone !== currentUser.phone) {
      if (phone.length < 11) {
        return res.status(400).json({ message: "O telefone deve ter pelo menos 11 dígitos!" });
      }

      if (!/^\d+$/.test(phone)) {
        return res.status(400).json({ message: "O telefone deve conter apenas números!" });
      }

      const existPhone = await prisma.user.findUnique({
        where: { phone },
      });

      if (existPhone && existPhone.id !== userId) {
        return res.status(400).json({ message: "Já existe uma conta com esse número!" });
      }

      updateData.phone = phone;
      hasChanges = true;
    }

    if (address && address !== currentUser.address) {
      if (address.length < 5) {
        return res.status(400).json({ message: "O endereço deve ter pelo menos 5 caracteres!" });
      }
      updateData.address = address;
      hasChanges = true;
    }

    if (password) {
      const isSamePassword = await bcrypt.compare(password, currentUser.password);
      if (!isSamePassword) {
        if (password.length < 4) {
          return res.status(400).json({ message: "A senha deve ter pelo menos 4 caracteres!" });
        }
        const salt = await bcrypt.genSalt(10);
        updateData.password = await bcrypt.hash(password, salt);
        hasChanges = true;
      }
    }

    // Se não houver mudanças reais
    if (!hasChanges) {
      return res.status(200).json({ 
        message: "Nenhum dado foi alterado (valores idênticos aos atuais).",
        user: {
          id: currentUser.id,
          name: currentUser.name,
          email: currentUser.email,
          phone: currentUser.phone,
          address: currentUser.address,
          createdAt: currentUser.createdAt,
        }
      });
    }

    // Executa a atualização apenas se houver mudanças
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: updateData,
    });

    res.status(200).json({
      message: "Usuário atualizado com sucesso",
      updatedUser: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        phone: updatedUser.phone,
        address: updatedUser.address,
        createdAt: updatedUser.createdAt,
      },
    });

  } catch (error) {
    if (error instanceof JsonWebTokenError) {
      return res.status(401).json({ message: "Token inválido." });
    }

    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2025') {
        return res.status(404).json({ message: "Usuário não encontrado." });
      }
      return res.status(400).json({ message: "Erro na requisição ao banco de dados." });
    }

    console.error("Erro ao tentar atualizar o usuário:", error);
    const errorMessage = error instanceof Error ? error.message : "Erro desconhecido.";
    res.status(500).json({ message: "Erro no servidor.", error: errorMessage });
  }
};