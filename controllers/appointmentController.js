const appointmentService = require('../services/appointmentService');

exports.createAppointment = async (req, res, next) => {
  const { idUsuario, dataAgendamento, horaAgendamento, descricao } = req.body;

  try {
    const result = await appointmentService.createAppointment(idUsuario, dataAgendamento, horaAgendamento, descricao);
    res.status(201).json({ success: true, message: 'Agendamento criado com sucesso!' });
  } catch (error) {
    next(error);
  }
};

exports.getAppointments = async (req, res, next) => {
  const { idUsuario } = req.params;

  try {
    const appointments = await appointmentService.getUserAppointments(idUsuario);
    if (!appointments) {
      return res.status(404).json({ success: false, message: 'Nenhum agendamento encontrado.' });
    }
    res.status(200).json({ success: true, appointments });
  } catch (error) {
    next(error);
  }
};
