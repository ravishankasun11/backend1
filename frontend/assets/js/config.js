const express = require('express');
const router = express.Router();

router.get('/config', (req, res) => {
    res.json({
        googleClientId: process.env.GOOGLE_CLIENT_ID
    });
});

module.exports = router;