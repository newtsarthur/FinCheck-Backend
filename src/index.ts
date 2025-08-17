import express from 'express';
import type { Application, Request, Response, NextFunction } from 'express';
import publicRoutes from './routes/public';
import privateRoutes from './routes/private';
import auth from './middlewares/auth';
import dotenv from 'dotenv';
import cors from 'cors';


dotenv.config();


const port = process.env.PORT || 3000;


const app: Application = express();


app.use(cors({
  origin: process.env.FRONTEND_URL || "https://localhost:5173",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));


app.use(express.json());


app.use('/', publicRoutes);


app.use('/', auth, privateRoutes);

app.listen(port, () => {
  console.log(`Server rodando na porta ${port}`);
});
