import express from 'express';
import type { Router } from 'express';
import { register, login } from '../controllers/user/userController';

// Cria uma instância de Router
const router: Router = express.Router();

// Rotas de autenticação
router.post('/register', register);
router.post('/login', login);

// Rotas para pets podem ser adicionadas aqui quando necessário
// import { getPet, getPetId, registerPet } from '../controllers/pets/petControllers.js';
// router.get('/pets', getPet);
// router.get('/pets/:id', getPetId);
// router.post('/pets', registerPet);

export default router;
