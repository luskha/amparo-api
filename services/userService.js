const pool = require('../config/db');
const bcrypt = require('bcryptjs');

exports.createUser = async (userData) => {
  const { tipoUsuario, nome, cpf, telefone, email, senha, dataNascimento, endereco, cep, numeroEmergencia, diasAtendimento, areaAtuacao, outrosArea } = userData;

  const hashedPassword = await bcrypt.hash(senha, 10);

  const query = `
    INSERT INTO amparousers (tipoUsuario, nome, cpf, telefone, email, senha, dataNascimento, endereco, cep, numeroEmergencia, diasAtendimento, areaAtuacao, outrosArea)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
  `;

  const values = [tipoUsuario, nome, cpf, telefone, email, hashedPassword, dataNascimento, endereco, cep, numeroEmergencia, diasAtendimento, areaAtuacao, outrosArea];

  await pool.query(query, values);
};

exports.getEmergencyContact = async (id) => {
  const result = await pool.query('SELECT numeroEmergencia FROM amparousers WHERE id = $1', [id]);
  if (result.rows.length > 0) {
    return result.rows[0].numeroemergencia;
  }
  return null;
};

// Nova função para obter dados do usuário
exports.getUserById = async (id) => {
  const query = `
    SELECT tipoUsuario, nome, cpf, telefone, email, dataNascimento, endereco, cep, numeroEmergencia, diasAtendimento, areaAtuacao, outrosArea
    FROM amparousers
    WHERE id = $1
  `;
  const result = await pool.query(query, [id]);
  if (result.rows.length > 0) {
    return result.rows[0];
  }
  return null;
};
