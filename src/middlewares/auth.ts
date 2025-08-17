import jwt from 'jsonwebtoken';
import type { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';

dotenv.config();

interface AuthRequest extends Request {
  userId?: string;
}

const JWT_SECRET = process.env.JWT_SECRET;


const auth = (req: AuthRequest, res: Response, next: NextFunction) => {
  const token = req.headers.authorization || "";

  if (!token) {
    return res.status(400).json({ message: "Acesso Negado" });
  }

  try {

    const decoded = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET as string) as { id: string };

    req.userId = decoded.id;

    next();
  } catch (error) {
    return res.status(401).json({ message: "Token Inválido" });
  }
};

export default auth;