const express = require('express');
const router = express.Router();

// Exemplo de rota de autenticação
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (email && password) {
    res.status(200).json({ message: 'Login bem-sucedido!' });
  } else {
    res.status(400).json({ message: 'Dados inválidos!' });
  }
});

// Exemplo de registro
router.post('/register', (req, res) => {
  res.status(201).json({ message: 'Usuário registrado com sucesso!' });
});

module.exports = router;
