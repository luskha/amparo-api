const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config(); // Carrega as variáveis do arquivo .env
const bcrypt = require('bcryptjs'); // Para hash de senhas
const app = express();

// Conexão com o banco de dados PostgreSQL utilizando as variáveis de ambiente
const pool = new Pool({
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT || 5432, // Adicione a porta como 5432 por padrão
  ssl: {
    rejectUnauthorized: false,
  },
});

app.use(cors());
app.use(bodyParser.json());

// Rota de cadastro de usuários
app.post('/cadastro', async (req, res) => {
  const {
    tipoUsuario, nome, cpf, telefone, email, senha, dataNascimento,
    endereco, cep, certificadoRegistro, nomeInstituicao,
    horariosAtendimento, nomeFantasia, horariosFuncionamento
  } = req.body;

  try {
    // Verificar se o email já existe
    const emailExistente = await pool.query('SELECT * FROM amparousers WHERE email = $1', [email]);
    if (emailExistente.rows.length > 0) {
      return res.status(400).send({ success: false, message: 'E-mail já cadastrado.' });
    }

    // Verificar se o telefone já existe
    const telefoneExistente = await pool.query('SELECT * FROM amparousers WHERE telefone = $1', [telefone]);
    if (telefoneExistente.rows.length > 0) {
      return res.status(400).send({ success: false, message: 'Número de telefone já cadastrado.' });
    }

    // Verificar se o CPF já existe
    const cpfExistente = await pool.query('SELECT * FROM amparousers WHERE cpf = $1', [cpf]);
    if (cpfExistente.rows.length > 0) {
      return res.status(400).send({ success: false, message: 'CPF já cadastrado.' });
    }

    // Hash da senha antes de armazená-la
    const hashedPassword = await bcrypt.hash(senha, 10);

    // Se tudo estiver ok, insira o novo usuário no banco
    await pool.query(
      `INSERT INTO amparousers (
        tipoUsuario, nome, cpf, telefone, email, senha, dataNascimento,
        endereco, cep, certificadoRegistro, nomeInstituicao,
        horariosAtendimento, nomeFantasia, horariosFuncionamento
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      [
        tipoUsuario, nome, cpf, telefone, email, hashedPassword, dataNascimento,
        endereco, cep, certificadoRegistro, nomeInstituicao,
        horariosAtendimento, nomeFantasia, horariosFuncionamento
      ]
    );

    res.status(201).send({ success: true, message: 'Usuário cadastrado com sucesso!' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send({ success: false, message: 'Erro ao cadastrar o usuário.' });
  }
});

// Rota de login
app.post('/login', async (req, res) => {
  const { email, senha } = req.body;

  try {
    const result = await pool.query('SELECT * FROM amparousers WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).send({ success: false, message: 'E-mail ou senha inválidos.' });
    }

    const user = result.rows[0];

    // Verificar se a senha está correta
    const isMatch = await bcrypt.compare(senha, user.senha);
    if (!isMatch) {
      return res.status(400).send({ success: false, message: 'E-mail ou senha inválidos.' });
    }

    // Aqui você pode retornar um token JWT ou uma resposta com os dados do usuário
    res.status(200).send({ success: true, message: 'Login bem-sucedido!', user });
  } catch (err) {
    console.error(err.message);
    res.status(500).send({ success: false, message: 'Erro ao fazer login.' });
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
