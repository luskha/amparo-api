const { validationResult } = require('express-validator');
const authService = require('../services/authService');

// Login do usuário
exports.login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Dados inválidos!' });
    }

    const user = await authService.loginUser(email, password);
    if (user) {
      return res.status(200).json({ success: true, message: 'Login bem-sucedido!', user });
    }

    return res.status(401).json({ success: false, message: 'Credenciais inválidas!' });
  } catch (error) {
    next(error);
  }
};

// Registro de novo usuário
exports.register = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Dados inválidos!' });
    }

    const newUser = await authService.registerUser(email, password);
    res.status(201).json({ success: true, message: 'Usuário registrado com sucesso!', user: newUser });
  } catch (error) {
    next(error);
  }
};
