const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { errorMiddleware } = require('./middlewares/errorMiddleware');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const appointmentRoutes = require('./routes/appointmentRoutes');
const medicationRoutes = require('./routes/medicationRoutes');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(bodyParser.json());

// Rotas
app.use('/auth', authRoutes);  // /auth/login, /auth/register
app.use('/users', userRoutes);  // /users para cadastrar usuário
app.use('/appointments', appointmentRoutes);
app.use('/medications', medicationRoutes);

// Middleware de erros
app.use(errorMiddleware);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
