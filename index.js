'use strict';
const _ = require('underscore');
const assert = require('assert');
const bcrypt = require('bcryptjs');
const express = require('express');
const validator = require('validator');
const rand_token = require('rand-token');
const winston = require('winston');
const config = require('./lib/config.js');

module.exports = function(opt, cb){
    opt = _.defaults(opt||{}, {
        config: false,
        port: 8080,
        proxy: 0,
        engine: 'ejs',
        cookie: {
            name: 'wexpress',
            secret: 'secret',
            age: 30*86400000,
        },
        json: true,
        static: 'public',
        controllers: './controllers',
    });
    Object.assign(config, opt.config||{});
    config.db = config.db||require('mongop')(config.mongo_url, Object.keys(config.collections));
    const app = express();
    const server = require('http').Server(app);
    app.set('trust proxy', opt.proxy);
    app.set('view engine', opt.engine);
    app.use(require('cookie-session')({
        name: opt.cookie.name,
        secret: opt.cookie.secret,
        secureProxy: config.production,
        maxAge: opt.cookie.age,
    }));
    app.use(require('body-parser').urlencoded({extended: true}));
    if (opt.json)
        app.use(require('body-parser').json());
    if (!config.production)
        app.use(require('morgan')('dev'));
    if (opt.static)
        app.use(express.static(opt.static));
    app.use((req, res, next)=>{
        if (req.url.endsWith('/') && req.url.length>1)
            return res.redirect(req.url.substr(0, req.url.length-1));
        next();
    });
    app.use(module.express.session());
    if (cb)
        cb(app, server);
    const collections = opt.collections||config.collections;
    return Promise.all(Object.keys(collections).reduce((indexes, name)=>{
        indexes = indexes.concat((collections[name].unique||[]).map(key=>{
            return config.db.ensureIndex(key.split(',').reduce((o, k)=>{
                o[k.trim()] = 1;
                return o;
            }), {unique: true});
        }));
        indexes = indexes.concat((collections[name].index||[]).map(key=>{
            return config.db.ensureIndex(key.split(',').reduce((o, k)=>{
                o[k.trim().replace(/~/, '')] = k.match(/~/) ? 'text' : 1;
                return o;
            }));
        }));
    }, [])).then(()=>{
        if (opt.controllers)
        {
            const controllers = require('require-all')(opt.controllers);
            Object.keys(controllers).forEach(name=>app.use(`/${name}`, controllers[name]));
        }
        /*eslint-disable no-unused-vars */
        app.use((err, req, res, next)=>{
            winston.error('Server error', err);
            res.status(500).send(config.production ? 'Server Error' : err.stack);
        });
        /*eslint-enable no-unused-vars */
        return new Promise((resolve, reject)=>{
            server.listen(opt.port, resolve).on('error', reject);
        });
    }).then(()=>app);
};
module.exports.config = config;
module.exports.register = opt=>{
    opt = _.defaults(opt||{}, {
        username: config.collections.user.unique.indexOf('username')>=0,
        verify: true,
        fields: [],
        on_duplicate: false,
    });
    return (req, res, next)=>{
        Promise.resolve(req.body).then(body=>{
            assert(validator.isEmail(body.email), `invalid email address: ${body.email}`);
            assert(body.password, 'missing password');
            assert(opt.username && body.username && !body.username.match(/\W/),
                `invalid username: ${body.username}`);
            return new Promise((resolve, reject)=>{
                bcrypt.hash(body.password, config.bcrypt, (err, hash)=>{
                    if (err)
                        return reject(err);
                    resolve(hash);
                });
            });
        }).then(hash=>{
            const user = Object.assign(_.pick(req.body, opt.fields||[]), {
                email: req.body.email,
                _email: validator.normalizeEmail(req.body.email),
                password: hash,
                ip: req.ip,
                random: Math.random(),
            });
            if (opt.username)
            {
                Object.assign(user, {
                    username: req.body.username,
                    _username: req.body.username.toLowerCase(),
                });
            }
            if (opt.verify)
            {
                user.verify = {
                    token: rand_token.generate(config.token.length),
                    expire: new Date(Date.now()+3*86400000),
                };
            }
            return config.db.user.insert(user);
        }).then(user=>{
            req.user = user;
            next();
        }).catch(err=>{
            if (err.name=='MongoError' && err.code==11000 && opt.on_duplicate)
                return opt.on_duplicate(req, res, next);
            next(err);
        });
    };
};
module.exports.login = opt=>{
    opt = _.defaults(opt||{}, {
        on_invalid_login: false,
        on_not_verified: false,
    });
    return (req, res, next)=>{
        assert((req.body.email||req.body.username) && req.body.password, 'missing email/password field');
        const query = {};
        if (req.body.email)
            query._email = validator.normalizeEmail(req.body.email);
        else
            query._username = req.body.username.toLowerCase();
        config.db.user.findOne(query).then(user=>{
            if (!user)
            {
                winston.info('no account found: %s', req.body.email||req.body.username, req.body);
                return null;
            }
            return new Promise((resolve, reject)=>{
                bcrypt.compare(req.body.password, user.password, (err, res)=>{
                    if (err)
                        return reject(err);
                    resolve(res ? user : null);
                });
            });
        }).then(user=>{
            req.user = user;
            if (!user)
            {
                winston.info('invalid password: %s', req.body.email||req.body.username, req.body);
                if (opt.on_invalid_login)
                    return opt.on_invalid_login(req, res, next);
                req.user = null;
                return next();
            }
            if (user.verify && !user.verified)
            {
                winston.info('user not verified: %s', req.body.email||req.body.username, user);
                return config.db.user.findAndModify({
                    query: {_id: user._id},
                    update: {$set: {verify: {
                        token: rand_token.generate(config.token.length),
                        expire: new Date(Date.now()+3*86400000),
                    }}},
                    new: true,
                }).then(user=>{
                    req.user = user;
                    if (opt.on_not_verified)
                        return opt.on_not_verified(req, res, next);
                    req.user = null;
                    next();
                });
            }
            return Promise.resolve(user.token).then(token=>{
                if (token && token.expire.getTime()>Date.now())
                    return user;
                return config.db.user.findAndModify({
                    query: {_id: user._id},
                    update: {$set: {token: {
                        token: rand_token.generate(config.token.length),
                        expire: new Date(Date.now()+(config.token.age||86400000)),
                    }}},
                    new: true,
                });
            }).then(user=>{
                req.user = user;
                req.session.token = user.token.token;
                next();
            });
        }).catch(next);
    };
};
module.exports.verify = ()=>{
    return (req, res, next)=>{
        config.db.user.findAndModify({
            query: {
                'verify.token': req.params.token,
                'verify.expire': {$gt: new Date()},
            },
            update: {
                $set: {verified: true},
                $unset: {verify: ''},
            },
            new: true,
        }).then(user=>{
            req.user = user;
            next();
        }).catch(next);
    };
};
module.exports.logout = ()=>{
    return (req, res, next)=>{
        if (req.user)
        {
            config.db.user.findAndModify({
                query: {_id: req.user._id},
                update: {$unset: {token: ''}},
            });
        }
        req.session = null;
        next();
    };
};
module.exports.reset = ()=>{
    return (req, res, next)=>{
        if (req.params.token)
        {
            return config.db.user.findOne({
                'reset.token': req.params.token,
                'reset.expire': {$gt: new Date()},
            }).then(user=>{
                req.user = user;
                next();
            }).catch(next);
        }
        assert(req.body.email||req.body.username, 'missing login field');
        const query = {};
        if (req.body.email)
            query._email = validator.normalizeEmail(req.body.email);
        else
            query._username = req.body.username.toLowerCase();
        config.db.user.findAndModify({
            query: query,
            update: {$set: {reset: {
                token: rand_token.generate(config.token.length),
                expire: new Date(Date.now()+3*86400000),
            }}},
            new: true,
        }).then(user=>{
            req.user = user;
            next();
        }).catch(next);
    };
};
module.exports.new_password = ()=>{
    return (req, res, next)=>{
        assert(req.body.token && req.body.password, 'missing token/password field');
        Promise.resolve(req.body).then(body=>new Promise((resolve, reject)=>{
            bcrypt.hash(body.password, config.bcrypt, (err, hash)=>{
                if (err)
                    return reject(err);
                resolve(hash);
            });
        })).then(hash=>config.db.user.findAndModify({
            query: {
                'reset.token': req.body.token,
                'reset.expire': {$gt: new Date()},
            },
            update: {
                $set: {password: hash},
                $unset: {reset: ''},
            },
            new: true,
        })).then(user=>{
            req.user = user;
            next();
        }).catch(next);
    };
};
module.exports.session = ()=>{
    return (req, res, next)=>{
        req.user = res.locals.user = null;
        if (!req.session.token)
            return next();
        config.db.user.findOne({
            'token.token': req.session.token,
            'token.expire': {$gt: new Date()},
        }).then(user=>{
            req.user = res.locals.user = user;
            next();
        }).catch(next);
    };
};
