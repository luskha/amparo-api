const pool = require('../config/db');
const bcrypt = require('bcryptjs');

exports.loginUser = async (email, senha) => {
  const query = 'SELECT * FROM amparousers WHERE email = $1';
  const result = await pool.query(query, [email]);

  if (result.rows.length > 0) {
    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(senha, user.senha);

    if (isPasswordValid) {
      delete user.senha; // Remova a senha antes de retornar os dados
      return user;
    }
  }

  return null;
};
