const pool = require('../config/db');
const bcrypt = require('bcryptjs');

exports.loginUser = async (email, password, userType) => {
  const query = 'SELECT * FROM amparousers WHERE email = $1 and tipousuario = $2';
  const result = await pool.query(query, [email, userType]);

  if (result.rows.length > 0) {
    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.senha);

    if (isPasswordValid) {
      delete user.senha; // Remova a password antes de retornar os dados
      return user;
    }
  }

  return null;
};
