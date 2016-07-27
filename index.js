'use strict';
const _ = require('lodash');
const assert = require('assert');
const Promise = require('bluebird');
const express = require('express');
const mongojs = require('mongojs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const base58 = require('bs58');

module.exports = opt=>{
    opt = opt||{};
    opt.cookie = opt.cookie||{};
    const db = mongojs(opt.mongo_url||process.env.MONGO_URL||
        'mongodb://127.0.0.1:27017/wexpress');
    const user = db.collection(opt.collection||'user');
    const findOne = Promise.promisify(user.findOne, {context: user});
    const findAndModify = Promise.promisify(user.findAndModify, {context: user});
    const insert = Promise.promisify(user.insert, {context: user});
    const token = ()=>Promise.promisify(crypto.randomBytes)(opt.token||32)
        .then(base58.encode);
    const hash = password=>Promise.promisify(bcrypt.hash)(password, opt.bcrypt||10);
    const compare = (p1, p2)=>Promise.promisify(bcrypt.compare)(p1, p2);
    let platforms = require('require-all')(require('path').join(__dirname,
        'platforms'));
    if (Array.isArray(opt.platforms))
        platforms = _.pick(platforms, opt.platforms);
    else if (typeof opt.platforms=='object')
    {
        platforms = _.pick(platforms,
            Object.keys(opt.platforms).filter(key=>opt.platforms[key]));
    }
    else if (!opt.platforms)
        platforms = {};
    const app = express();
    if (!opt.stateless)
    {
        app.use(require('cookie-session')({
            name: opt.cookie.name||'wexpress',
            secret: opt.cookie.secret||process.env.COOKIE_SECRET||
                throw new Error('missing cookie secret'),
            secureProxy: opt.cookie.secureProxy!==undefined ?
                opt.cookie.secureProxy : process.env.NODE_ENV=='production',
            maxAge: opt.cookie.age||365*86400000,
        }));
    }
    app.use(require('body-parser').urlencoded({extended: true}));
    if (opt.json)
        app.use(require('body-parser').json());
    app.use(Promise.coroutine(function*(req, res, next){
        try {
            const token = opt.stateless ? req.query.token||req.body.token :
                req.session.token;
            req.user = token && (yield findOne({token: token})) || null;
            next();
        } catch(err) { next(err); }
    }));
    app.post('/login', Promise.coroutine(function*(req, res, next){
        try {
            if (req.body.password)
            {
                let query = {password: {$exists: true}};
                if (req.body.email)
                    query.email = req.body.email;
                else if (req.body.username)
                    query.username = req.body.username;
                else
                    return res.status(400).end();
                let user = yield findOne(query);
                if (!user || !(yield compare(req.body.password, user.password)))
                    return opt.middleware ? next() : res.status(401).end();
                if (opt.verify && !user.verified)
                {
                    let user = yield findAndModify({
                        query: {_id: user._id},
                        update: {$set: {verify: {
                            token: yield token(),
                            timestamp: new Date(),
                            ua: req.headers['user-agent'],
                            ip: req.ip,
                        }}},
                        new: true,
                    });
                    yield Promise.method(opt.verify)(user);
                    return opt.middleware ? next() : res.status(403).end();
                }
                req.user = user;
                if (!opt.stateless)
                    req.session.token = user.token.token;
                return opt.middleware ? next() : res.json({token: user.token.token});
            }
            for (let name in platforms)
            {
                if (!req.body[name])
                    continue;
                let data = yield platforms[name](req.body[name]);
                if (!data || !data.email)
                    return opt.middleware ? next() : res.status(401).end();
                req.user = yield findAndModify({
                    query: {email: data.email},
                    update: {
                        $set: data,
                        $setOnInsert: Object.assign({
                            email: data.email,
                            ip: req.ip,
                            ua: req.headers['user-agent'],
                            random: Math.random(),
                            token: {
                                token: yield token(),
                                timestamp: new Date(),
                                ua: req.headers['user-agent'],
                                ip: req.ip,
                            },
                        }, opt.verify ? {verified: true} : {}),
                    },
                    new: true,
                    upsert: true,
                });
                assert(res.user, 'could not insert new user');
                if (!opt.stateless)
                    req.session.token = req.user.token.token;
                return opt.middleware ? next() : res.json({token: req.user.token.token});
            }
            res.status(400).end();
        } catch(err) { next(err); }
    }));
    app.post('/register', Promise.coroutine(function*(req, res, next){
        try {
            if (!req.body.email)
                return res.status(400).end();
            if (opt.username && !req.body.username)
                return res.status(400).end();
            let user = {
                email: req.body.email,
                password: yield hash(req.body.password),
                ip: req.ip,
                ua: req.headers['user-agent'],
                random: Math.random(),
                token: {
                    token: yield token(),
                    timestamp: new Date(),
                    ua: req.headers['user-agent'],
                    ip: req.ip,
                },
            };
            if (opt.gravatar)
            {
                const md5 = crypto.createHash('md5')
                    .update(req.body.email.trim().toLowerCase()).digest('hex');
                Object.assign(user, {
                    avatar: `https://www.gravatar.com/avatar/${md5}?s=200&d=identicon`,
                    thumbnail: `https://www.gravatar.com/avatar/${md5}?s=50&d=identicon`,
                });
            }
            if (req.body.username)
                user.username = req.body.username;
            if (opt.verify)
            {
                user.verify = {
                    token: yield token(),
                    timestamp: new Date(),
                    ua: req.headers['user-agent'],
                    ip: req.ip,
                };
            }
            try {
                req.user = yield insert(user);
            } catch(err) {
                if (err.name=='MongoError' && err.code==11000 && !opt.middleware)
                    return res.status(409).end();
                throw err;
            }
            if (opt.verify)
            {
                yield Promise.method(opt.verify)(req.user);
                return opt.middleware ? next() : res.status(202).end();
            }
            if (!opt.stateless)
                req.session.token = req.user.token.token;
            return opt.middleware ? next() : res.json({token: req.user.token.token});
        } catch(err) { next(err); }
    }));
    if (opt.verify)
    {
        app.get('/verify', Promise.coroutine(function*(req, res, next){
            try {
                req.user = yield findAndModify({
                    query: {'verify.token': req.query.token||''},
                    update: {
                        $set: {verified: true},
                        $unset: {verify: ''},
                    },
                    new: true,
                });
                if (opt.middleware)
                    return next();
                if (!req.user)
                    return res.status(410).end();
                res.status(200).end();
            } catch(err) { next(err); }
        }));
    }
    if (opt.reset)
    {
        app.post('/reset', Promise.coroutine(function*(req, res, next){
            try {
                if (req.body.token)
                {
                    req.user = yield findAndModify({
                        query: {'reset.token': req.body.token},
                        update: {
                            $set: {password: yield hash(req.body.password||'')},
                            $unset: {reset: ''},
                        },
                        new: true,
                    });
                    if (opt.middleware)
                        return next();
                    if (!req.user)
                        return res.status(410).end();
                    return res.status(200).end();
                }
                let query = {};
                if (req.body.email)
                    query.email = req.body.email;
                else if (req.body.username)
                    query.username = req.body.username;
                else
                    return res.status(400).end();
                req.user = yield findAndModify({
                    query: query,
                    update: {$set: {reset: {
                        token: yield token(),
                        timestamp: new Date(),
                        ua: req.headers['user-agent'],
                        ip: req.ip,
                    }}},
                    new: true,
                });
                if (req.user)
                    yield Promise.method(opt.reset)(req.user);
                return opt.middleware ? next() : res.status(202).end();
            } catch(err) { next(err); }
        }));
        app.get('/reset', Promise.coroutine(function*(req, res, next){
            try {
                req.user = yield findOne({'reset.token': req.query.token||''});
                if (opt.middleware)
                    return next();
                if (!req.user)
                    return res.status(410).end();
                res.json({token: req.user.reset.token});
            } catch(err) { next(err); }
        }));
    }
    app.get('/logout', Promise.coroutine(function*(req, res, next){
        try {
            if (!req.user)
                return opt.middleware ? next() : res.status(403).end();
            if (+(req.query.all||req.body.all))
            {
                yield findAndModify({
                    query: {_id: req.user._id},
                    update: {$set: {token: {
                        token: yield token(),
                        timestamp: new Date(),
                        ua: req.headers['user-agent'],
                        ip: req.ip,
                    }}},
                });
            }
            if (!opt.stateless)
                req.session = null;
            return opt.middleware ? next() : res.status(205).end();
        } catch(err) { next(err); }
    }));
    return app;
};
