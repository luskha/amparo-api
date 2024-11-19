const { validationResult } = require('express-validator');
const authService = require('../services/authService');

exports.login = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { email, senha } = req.body;

  try {
    const token = await authService.loginUser(email, senha);
    res.status(200).json({ success: true, token });
  } catch (error) {
    next(error);
  }
};
