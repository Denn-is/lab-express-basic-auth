'use strict';

// User model goes here

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    //   unique: true,
      trim: true
    },
    passwordHash: {
      type: String,
      required: true
    },
  },
  {
    timestamps: true
  }
);

const User = mongoose.model('User', userSchema);

module.exports = User;