const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');  // Certifique-se de que está importando o controlador correto

// Rota POST para adicionar um novo usuário
router.post('/register', userController.registerUser); // Usa a função de registro do controlador

// Rota GET para obter informações do usuário pelo ID
router.get('/:id', async (req, res) => {
  const userId = req.params.id;
  try {
    const user = await userService.getUserById(userId);  // Chama o serviço para buscar o usuário pelo ID
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

// Outras rotas se necessário (por exemplo, para listagem de usuários)

module.exports = router;
