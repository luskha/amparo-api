const medicationService = require('../services/medicationService');

exports.addMedication = async (req, res, next) => {
  const { idUsuario, nomeMedicamento, vezesPorDia, periodoUso, primeiraDose } = req.body;

  try {
    await medicationService.addMedication(idUsuario, nomeMedicamento, vezesPorDia, periodoUso, primeiraDose);
    res.status(201).json({ success: true, message: 'Medicamento registrado com sucesso!' });
  } catch (error) {
    next(error);
  }
};

exports.getMedications = async (req, res, next) => {
  const { idUsuario } = req.params;

  try {
    const medications = await medicationService.getUserMedications(idUsuario);
    if (!medications) {
      return res.status(404).json({ success: false, message: 'Nenhum medicamento encontrado.' });
    }
    res.status(200).json({ success: true, medications });
  } catch (error) {
    next(error);
  }
};
