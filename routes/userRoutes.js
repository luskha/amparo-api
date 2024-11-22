const express = require('express');
const router = express.Router();
const userService = require('../services/userService');

// Obter lista de usuários
router.get('/', (req, res) => {
  res.status(200).json({ message: 'Lista de usuários' });
});

// Adicionar novo usuário
router.post('/', (req, res) => {
  res.status(201).json({ message: 'Usuário criado com sucesso!' });
});

// Obter informações do usuário pelo ID
router.get('/:id', async (req, res) => {
  const userId = req.params.id;
  try {
    const user = await userService.getUserById(userId);
    if (user) {
      res.status(200).json(user);
    } else {
      res.status(404).json({ message: 'Usuário não encontrado' });
    }
  } catch (error) {
    console.error('Erro ao obter dados do usuário:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

module.exports = router;
