const { validationResult } = require('express-validator');
const authService = require('../services/authService');

exports.login = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { email, senha } = req.body;

  try {
    const user = await authService.loginUser(email, senha);
    if (user) {
      res.status(200).json({ success: true, user });
    } else {
      res.status(401).json({ success: false, message: 'Credenciais inválidas' });
    }
  } catch (error) {
    next(error);
  }
};
