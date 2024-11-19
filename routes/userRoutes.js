const express = require('express');
const router = express.Router();

// Obter lista de usuários
router.get('/', (req, res) => {
  res.status(200).json({ message: 'Lista de usuários' });
});

// Adicionar novo usuário
router.post('/', (req, res) => {
  res.status(201).json({ message: 'Usuário criado com sucesso!' });
});

module.exports = router;
