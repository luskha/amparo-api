const pool = require('../config/db');
const bcrypt = require('bcryptjs');

exports.createUser = async (userData) => {
  const { tipousuario, nome, cpf, telefone, email, senha, datanascimento, endereco, cep, numeroemergencia, diasatendimento, areaatuacao, outrosarea } = userData;

  const hashedPassword = await bcrypt.hash(senha, 10);

  const query = `
    INSERT INTO amparousers (tipousuario, nome, cpf, telefone, email, senha, datanascimento, endereco, cep, numeroemergencia, diasatendimento, areaatuacao, outrosarea)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
    RETURNING id, tipousuario, nome, cpf, telefone, email, datanascimento, endereco, cep, numeroemergencia, diasatendimento, areaatuacao, outrosarea;
  `;

  const values = [tipousuario, nome, cpf, telefone, email, hashedPassword, datanascimento, endereco, cep, numeroemergencia, diasatendimento, areaatuacao, outrosarea];

  const result = await pool.query(query, values);
  return result.rows[0];  // Retorna o usuário criado
};

exports.getEmergencyContact = async (id) => {
  const result = await pool.query('SELECT numeroemergencia FROM amparousers WHERE id = $1', [id]);
  if (result.rows.length > 0) {
    return result.rows[0].numeroemergencia;  // Corrigido para o nome correto da coluna 'numeroemergencia'
  }
  return null;
};

// Nova função para obter dados do usuário
exports.getUserById = async (id) => {
  const query = `
    SELECT tipousuario, nome, cpf, telefone, email, datanascimento, endereco, cep, numeroemergencia, diasatendimento, areaatuacao, outrosarea
    FROM amparousers
    WHERE id = $1
  `;
  const result = await pool.query(query, [id]);
  if (result.rows.length > 0) {
    return result.rows[0];
  }
  return null;
};
