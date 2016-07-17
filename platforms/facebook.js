'use strict';
const Promise = require('bluebird');
const request = Promise.promisify(require('request'));

module.exports = Promise.coroutine(function*(token){
    const res = yield request({
        url: 'https://graph.facebook.com/v2.6/me',
        qs: {access_token: token, fields: 'name,email'},
        json: true,
    });
    if (res.body.error)
        throw new Error(res.body.error.message);
    return {
        email: res.body.email,
        avatar: `//graph.facebook.com/${res.body.id}/picture?type=large`,
        thumbnail: `//graph.facebook.com/${res.body.id}/picture?type=small`,
        facebook: Object.assign(res.body, {access_token: token}),
    };
});
