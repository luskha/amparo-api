const pool = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.loginUser = async (email, senha) => {
  const result = await pool.query('SELECT * FROM amparousers WHERE email = $1', [email]);
  if (result.rows.length === 0) {
    throw new Error('E-mail ou senha inválidos.');
  }

  const user = result.rows[0];

  const isMatch = await bcrypt.compare(senha, user.senha);
  if (!isMatch) {
    throw new Error('E-mail ou senha inválidos.');
  }

  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  return token;
};
