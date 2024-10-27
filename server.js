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
  port: process.env.PGPORT || 5432,
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
    horariosAtendimento, nomeFantasia, horariosFuncionamento, numeroEmergencia
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

    // Preparar valores para campos opcionais
    const certificadoRegistroValue = certificadoRegistro || null;
    const nomeInstituicaoValue = nomeInstituicao || null;
    const horariosAtendimentoValue = horariosAtendimento || null;
    const nomeFantasiaValue = nomeFantasia || null;
    const horariosFuncionamentoValue = horariosFuncionamento || null;
    const numeroEmergenciaValue = numeroEmergencia || null;

    // Inserir novo usuário no banco
    await pool.query(
      `INSERT INTO amparousers (
        tipoUsuario, nome, cpf, telefone, email, senha, dataNascimento,
        endereco, cep, certificadoRegistro, nomeInstituicao,
        horariosAtendimento, nomeFantasia, horariosFuncionamento, numeroEmergencia
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        tipoUsuario, nome, cpf, telefone, email, hashedPassword, dataNascimento,
        endereco, cep, certificadoRegistroValue, nomeInstituicaoValue,
        horariosAtendimentoValue, nomeFantasiaValue, horariosFuncionamentoValue, numeroEmergenciaValue
      ]
    );

    res.status(201).send({ success: true, message: 'Usuário cadastrado com sucesso!' });
  } catch (err) {
    console.error('Erro no cadastro:', err);
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

    res.status(200).send({ success: true, message: 'Login bem-sucedido!', user });
  } catch (err) {
    console.error(err.message);
    res.status(500).send({ success: false, message: 'Erro ao fazer login.' });
  }
});

// Rota para obter o número de emergência de um usuário pelo ID
app.get('/user/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT numeroEmergencia FROM amparousers WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).send({ success: false, message: 'Usuário não encontrado.' });
    }

    const { numeroemergencia } = result.rows[0];
    res.status(200).send({ success: true, numeroEmergencia: numeroemergencia });
  } catch (err) {
    console.error(err.message);
    res.status(500).send({ success: false, message: 'Erro ao buscar o número de emergência.' });
  }
});

// Rota para criar um novo agendamento
app.post('/agendamentos', async (req, res) => {
  const { idUsuario, dataAgendamento, horaAgendamento, descricao } = req.body;

  try {
    const usuarioExistente = await pool.query('SELECT * FROM amparousers WHERE id = $1', [idUsuario]);
    if (usuarioExistente.rows.length === 0) {
      return res.status(404).send({ success: false, message: 'Usuário não encontrado.' });
    }

    await pool.query(
      `INSERT INTO agendamentos (idUsuario, dataAgendamento, horaAgendamento, descricao) 
       VALUES ($1, $2, $3, $4)`,
      [idUsuario, dataAgendamento, horaAgendamento, descricao]
    );

    res.status(201).send({ success: true, message: 'Agendamento criado com sucesso!' });
  } catch (err) {
    console.error('Erro ao criar agendamento:', err);
    res.status(500).send({ success: false, message: 'Erro ao criar agendamento.' });
  }
});

// Rota para criar um novo medicamento
app.post('/medicamentos', async (req, res) => {
  const { idUsuario, nomeMedicamento, vezesPorDia, periodoUso, primeiraDose } = req.body;

  try {
    const usuarioExistente = await pool.query('SELECT * FROM amparousers WHERE id = $1', [idUsuario]);
    if (usuarioExistente.rows.length === 0) {
      return res.status(404).send({ success: false, message: 'Usuário não encontrado.' });
    }

    await pool.query(
      `INSERT INTO medicamentos (idUsuario, nomeMedicamento, vezesPorDia, periodoUso, primeiraDose) 
       VALUES ($1, $2, $3, $4, $5)`,
      [idUsuario, nomeMedicamento, vezesPorDia, periodoUso, primeiraDose]
    );

    res.status(201).send({ success: true, message: 'Medicamento registrado com sucesso!' });
  } catch (err) {
    console.error('Erro ao registrar medicamento:', err);
    res.status(500).send({ success: false, message: 'Erro ao registrar medicamento.' });
  }
});

// Rota para listar os agendamentos de um usuário
app.get('/agendamentos/:idUsuario', async (req, res) => {
  const { idUsuario } = req.params;

  try {
    const result = await pool.query(
      'SELECT * FROM agendamentos WHERE idUsuario = $1 ORDER BY dataAgendamento, horaAgendamento', 
      [idUsuario]
    );

    if (result.rows.length === 0) {
      return res.status(404).send({ success: false, message: 'Nenhum agendamento encontrado.' });
    }

    res.status(200).send({ success: true, agendamentos: result.rows });
  } catch (err) {
    console.error('Erro ao buscar agendamentos:', err);
    res.status(500).send({ success: false, message: 'Erro ao buscar agendamentos.' });
  }
});

// Rota para listar os medicamentos de um usuário
app.get('/medicamentos/:idUsuario', async (req, res) => {
  const { idUsuario } = req.params;

  try {
    const result = await pool.query(
      'SELECT * FROM medicamentos WHERE idUsuario = $1 ORDER BY primeiraDose ASC',
      [idUsuario]
    );

    if (result.rows.length === 0) {
      return res.status(404).send({ success: false, message: 'Nenhum medicamento encontrado.' });
    }

    res.status(200).send({ success: true, medicamentos: result.rows });
  } catch (err) {
    console.error('Erro ao buscar medicamentos:', err);
    res.status(500).send({ success: false, message: 'Erro ao buscar medicamentos.' });
  }
});

// Configuração do servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
