const express = require('express');
const router = express.Router();

// Obter lista de consultas
router.get('/', (req, res) => {
  res.status(200).json({ message: 'Lista de consultas agendadas' });
});

// Agendar nova consulta
router.post('/', (req, res) => {
  res.status(201).json({ message: 'Consulta agendada com sucesso!' });
});

module.exports = router;
