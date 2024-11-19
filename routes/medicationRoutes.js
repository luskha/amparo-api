const express = require('express');
const router = express.Router();

// Obter lista de medicamentos
router.get('/', (req, res) => {
  res.status(200).json({ message: 'Lista de medicamentos' });
});

// Adicionar novo medicamento
router.post('/', (req, res) => {
  res.status(201).json({ message: 'Medicamento adicionado com sucesso!' });
});

// Atualizar medicamento
router.put('/:id', (req, res) => {
  const { id } = req.params;
  res.status(200).json({ message: `Medicamento ${id} atualizado com sucesso!` });
});

// Remover medicamento
router.delete('/:id', (req, res) => {
  const { id } = req.params;
  res.status(200).json({ message: `Medicamento ${id} removido com sucesso!` });
});

module.exports = router;
