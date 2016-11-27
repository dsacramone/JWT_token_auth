const User = require('../models/users'); // all users
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user) {
	// sub is short for 'subject', who does this token belong to
	// the subject, in this case, is this user, ie: user.id
	// "iat": issued at time, a jwt convention.
	const timestamp = new Date().getTime();
	return jwt.encode(
		{ sub: user.id,
			iat: timestamp
		}, config.secret)
}

exports.signin = function(req, res, next) {
	//user has already had their email and pw auth
	// give them a token
	res.send({token: tokenForUser(req.user)})
}


exports.signup = function(req, res, next) {
	const email = req.body.email;
	const pw = req.body.password;

	if(!email || !pw) {
		res.status(422).send({error: "Both email and password required"})
	}
// see if user with given email, exists
// look in db and check
	User.findOne({email: email}, (err, existingUser) => {
		if(err) {
			return next(err);
		}
// if email does exist, return error
		if(existingUser) {
			// we understand the request etc.. BUT, we can't use it. ie.. email already
			// exists.
			res.status(422).send({error: "email is in use"})
		}
		// if an email does not exist, save and create record
		// so, we use "new" on our User class
		const user = new User({
			email: email,
			password: pw
		})

			user.save( err => {
			if (err) {
					return next(err);
			}
			// saved nicely and now lets just respond with the payload
			// lets hand back a token, so we know the user is now logged in.
			// JWT : json web token
			res.json({ token: tokenForUser(user)});
		});

	});

}