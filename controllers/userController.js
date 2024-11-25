const { validationResult } = require('express-validator');
const userService = require('../services/userService');

exports.registerUser = async (req, res, next) => {
  console.log(req.body)
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  try {
    const result = await userService.createUser(req.body); // Chama o serviço para criar um usuário
    console.log(result)
    res.status(201).json({ success: true, message: 'Usuário cadastrado com sucesso!' });
  } catch (error) {
    next(error);
  }
};

exports.getEmergencyContact = async (req, res, next) => {
  const { id } = req.params;

  try {
    const emergencyContact = await userService.getEmergencyContact(id); // Chama o serviço para obter o contato de emergência
    if (!emergencyContact) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
    }
    res.status(200).json({ success: true, numeroemergencia: emergencyContact });
  } catch (error) {
    next(error);
  }
};

exports.createUser = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  try {
    const result = await userService.createUser(req.body);
    res.status(201).json({ success: true, message: 'Usuário criado com sucesso!' });
  } catch (error) {
    next(error);
  }
};
