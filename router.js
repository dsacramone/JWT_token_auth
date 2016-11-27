const Authentication = require('./controllers/authentication.js');
const passportService = require('./services/passport');
const passport = require('passport');

// session:false says not to use cookies, since we
// are using a token
const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', {session: false})

module.exports = app => {
	app.get('/', requireAuth, function(req, res) {
		res.send( {'user': 'valid'} );
	});

	app.post('/signin', requireSignin, Authentication.signin);
	app.post('/signup', Authentication.signup)

}