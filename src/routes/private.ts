import express from 'express';
import type { Application, Router, Request, Response, NextFunction } from 'express';
import { deleteUser, updateUser } from '../controllers/userController';

// A importação deve usar a extensão '.js' para ser compatível com as configurações do TypeScript
// e do Node.js

// import { deleteUser, updateUser } from '../controllers/users/userController.js';
// import { deletePet, updatePet } from '../controllers/pets/petControllers.js';
import auth from '../middlewares/auth.js'; 

// Cria uma instância de Router, tipada para o Express
const router: Router = express.Router();

// Delete user router
// O tipo 'Router' já sabe como lidar com as rotas
router.delete('/delete/:id', auth, deleteUser);

// Update user router
// A rota tem dois middlewares: 'auth' e 'updateUser'
router.put('/update/:id', auth, updateUser);

export default router;