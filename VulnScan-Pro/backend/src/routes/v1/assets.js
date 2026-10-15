const router = require('express').Router();
const auth = require('../../middleware/auth');
const authorize = require('../../middleware/rbac');
const { getAssets, getAsset, createAsset, updateAsset, deleteAsset } = require('../../controllers/assetController');

router.use(auth);
router.use(authorize('analyst'));

router.get('/', getAssets);
router.get('/:id', getAsset);
router.post('/', createAsset);
router.put('/:id', updateAsset);
router.delete('/:id', deleteAsset);

module.exports = router;
