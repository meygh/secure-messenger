function ensureAuthenticated(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
    res.status(401).send('Unauthorized: Please log in first.');
}

module.exports = ensureAuthenticated;