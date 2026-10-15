const Joi = require('joi');
const { Asset } = require('../models');
const { Op } = require('sequelize');

// ─── Validation ───
const assetSchema = Joi.object({
    name: Joi.string().min(1).max(255).required(),
    type: Joi.string().valid('ip', 'domain', 'subnet').required(),
    target: Joi.string().max(500).required(),
    description: Joi.string().max(1000).allow('', null),
});

/**
 * GET /assets
 */
const getAssets = async (req, res, next) => {
    try {
        const { page = 1, limit = 20, type, search } = req.query;
        const offset = (page - 1) * limit;

        const where = {};
        if (req.user.role !== 'admin') where.userId = req.user.id;
        if (type) where.type = type;
        if (search) {
            where[Op.or] = [
                { name: { [Op.iLike]: `%${search}%` } },
                { target: { [Op.iLike]: `%${search}%` } },
            ];
        }

        const { count, rows } = await Asset.findAndCountAll({
            where,
            limit: parseInt(limit),
            offset: parseInt(offset),
            order: [['createdAt', 'DESC']],
        });

        res.json({
            success: true,
            data: rows,
            pagination: { page: parseInt(page), limit: parseInt(limit), total: count },
        });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /assets/:id
 */
const getAsset = async (req, res, next) => {
    try {
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const asset = await Asset.findOne({ where });
        if (!asset) {
            return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Asset not found' } });
        }
        res.json({ success: true, data: asset });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /assets
 */
const createAsset = async (req, res, next) => {
    try {
        const { error, value } = assetSchema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const asset = await Asset.create({ ...value, userId: req.user.id });
        res.status(201).json({ success: true, data: asset, message: 'Asset created' });
    } catch (err) {
        next(err);
    }
};

/**
 * PUT /assets/:id
 */
const updateAsset = async (req, res, next) => {
    try {
        const { error, value } = assetSchema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const asset = await Asset.findOne({ where });
        if (!asset) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Asset not found' } });

        await asset.update(value);
        res.json({ success: true, data: asset, message: 'Asset updated' });
    } catch (err) {
        next(err);
    }
};

/**
 * DELETE /assets/:id
 */
const deleteAsset = async (req, res, next) => {
    try {
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const asset = await Asset.findOne({ where });
        if (!asset) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Asset not found' } });

        await asset.destroy();
        res.status(204).send();
    } catch (err) {
        next(err);
    }
};

module.exports = { getAssets, getAsset, createAsset, updateAsset, deleteAsset };
