'use strict';

module.exports = {
    production: process.env.NODE_ENV=='production',
    mongo_url: 'mongodb://127.0.0.1:27017/wexpress',
    bcrypt: 10,
    token: {
        length: 24,
        age: 30*86400000,
    },
    collections: {
        user: {
            index: ['token.token', 'verify.token', 'reset.token', 'random'],
            unique: ['email'],
        },
    },
};
