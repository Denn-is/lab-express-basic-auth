'use strict';

const { join } = require('path');
const express = require('express');
const createError = require('http-errors');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const sassMiddleware = require('node-sass-middleware');
const serveFavicon = require('serve-favicon');

const mongoose = require('mongoose');
const expressSession = require('express-session');
const connectMongo = require('connect-mongo');
const MongoStore = connectMongo(expressSession);

const indexRouter = require('./routes/index');
const User = require('./models/user');


const app = express();

// Setup view engine
app.set('views', join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(serveFavicon(join(__dirname, 'public/images', 'favicon.ico')));
app.use(express.static(join(__dirname, 'public')));
app.use(sassMiddleware({
  src: join(__dirname, 'public'),
  dest: join(__dirname, 'public'),
  outputStyle: process.env.NODE_ENV === 'development' ? 'nested' : 'compressed',
  sourceMap: true
}));

app.use(
  expressSession({
    // We need to pass a secure session secret to express session
    // in order for it to encrypt our password securely
    // This secret should not be changed after it's set
    secret: process.env.SESSION_SECRET,
    // Resaving ensures that the cookie is refreshed every time the user makes a request
    resave: true,
    // Don't set a cookie if we haven't initialized a session
    saveUninitialized: false,
    cookie: {
      maxAge: 60 * 60 * 24 * 15,
      // We should set this for security
      // cookie.sameSite prevents CSRF attacks
      sameSite: true,
      // cookie.httpOnly means the cookie is not readable by JavaScript
      httpOnly: true,
      // We're setting cookie.secure to true on non-development environments only
      // since in dev mode we're loading localhost throught http
      secure: process.env.NODE_ENV !== 'development'
    },
    // Mongo store is going to save the value of req.session in a database record
    // that will be loaded to req.session in every request
    store: new MongoStore({
      mongooseConnection: mongoose.connection,
      ttl: 60 * 60 * 24
    })
  })
);

// Deserializing user
// Checks if there's a user ID saved on the session
// If so, load the user from the database and bind it into req.user
app.use((req, res, next) => {
  const userId = req.session.user;
  if (userId) {
    User.findById(userId)
      .then(user => {
        req.user = user;
        // Set the user in the response locals, so it can be accessed from any view
        res.locals.user = req.user;
        // Go to the next middleware/controller
        next();
      })
      .catch(error => {
        next(error);
      });
  } else {
    // If there isn't a userId saved in the session,
    // go to the next middleware/controller
    next();
  }
});

app.use('/', indexRouter);

// Catch missing routes and forward to error handler
app.use((req, res, next) => {
  next(createError(404));
});

// Catch all error handler
app.use((error, req, res, next) => {
  // Set error information, with stack only available in development
  res.locals.message = error.message;
  res.locals.error = req.app.get('env') === 'development' ? error : {};

  res.status(error.status || 500);
  res.render('error');
});

module.exports = app;
