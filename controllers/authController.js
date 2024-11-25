const { validationResult } = require('express-validator');
const authService = require('../services/authService');  // Certifique-se de que userService seja o responsável por toda a lógica de autenticação e manipulação de usuários

// Login do usuário
exports.login = async (req, res, next) => {
  console.log(req.body)
  const { email, password, userType } = req.body;

  try {
    if (!email || !password || !userType) {
      return res.status(400).json({ success: false, message: 'Dados inválidos!' });
    }

    const user = await authService.loginUser(email, password, userType);  // Alterado para usar userService
    if (user) {
      console.log(user)
      return res.status(200).json({ success: true, message: 'Login bem-sucedido!', user });
    }

    return res.status(401).json({ success: false, message: 'Credenciais inválidas!' });
  } catch (error) {
    next(error);
  }
};

// Registro de novo usuário
exports.register = async (req, res, next) => {
  const { email, password, nome, telefone, tipousuario, datanascimento, endereco, cep, numeroemergencia, certificadoRegistro, horariosAtendimento, diasatendimento, areaatuacao } = req.body;

  try {
    if (!email || !password || !nome || !telefone || !tipousuario) {
      return res.status(400).json({ success: false, message: 'Dados inválidos!' });
    }

    // Usando o userService para registrar um novo usuário
    const newUser = await userService.createUser({
      email, 
      password, 
      nome, 
      telefone, 
      tipousuario, 
      datanascimento, 
      endereco, 
      cep, 
      numeroemergencia,
      certificadoRegistro: tipousuario === 'profissional' ? certificadoRegistro : null,
      horariosAtendimento: tipousuario === 'profissional' ? horariosAtendimento : null,
      diasatendimento: tipousuario === 'profissional' ? diasatendimento : null,
      areaatuacao: tipousuario === 'profissional' && areaatuacao === 'Outros' ? areaatuacao : null
    });

    res.status(201).json({ success: true, message: 'Usuário registrado com sucesso!', user: newUser });
  } catch (error) {
    next(error);
  }
};
