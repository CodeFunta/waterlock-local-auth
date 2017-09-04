'use strict';

var _ = require('lodash');
var wla = require('./waterlock-local-auth');
var authConfig = wla.authConfig;

exports.attributes = function (attr) {
  var template = {
    email: {
      type: 'string',
      unique: true,
      required: true,
      isEmail: true
    },
    username: {
      type: 'string',
      unique: true,
    },
    password: {
      type: 'STRING',
      minLength: 8
    },
    resetToken: {
      model: 'resetToken'
    }
  };
  if (authConfig.useUserName) {
    template.username.required = true;
  }
  else if (!_.isUndefined(template.username.required)) {
    delete template.username.required;
  }
  _.merge(template, attr);
  _.merge(attr, template);
};

/**
 * used to hash the password
 * @param  {object}   values
 * @param  {Function} cb
 */
exports.beforeCreate = function (values) {
  if (!_.isUndefined(values.password)) {
    var bcrypt = require('bcrypt');
    var salt = bcrypt.genSaltSync(10);
    var hash = bcrypt.hashSync(values.password, salt);
    values.password = hash;
  }
};

/**
 * used to update the password hash if user is trying to update password
 * @param  {object}   values
 * @param  {Function} cb
 */
exports.beforeUpdate = function (values) {
  if (!_.isUndefined(values.password) && values.password !== null) {
    var bcrypt = require('bcrypt');
    var salt = bcrypt.genSaltSync(10);
    var hash = bcrypt.hashSync(values.password, salt);
    values.password = hash;
  }
};
