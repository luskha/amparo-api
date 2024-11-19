const errorMiddleware = (err, req, res, next) => {
    console.error('Erro:', err.message);
    res.status(500).json({ message: 'Ocorreu um erro no servidor!' });
  };
  
  module.exports = { errorMiddleware };
  