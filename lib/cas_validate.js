/*global require process console JSON __dirname */
var parseUrl = require('url').parse
var http = require('http')
var request = require('request')
var querystring = require('querystring')
var _ = require('underscore')
var winston = require("winston");

var env = process.env;

/**
 * CAS validate:  validate requests via CAS service tickets
 *
 * Options:
 *
 *   - `serivce`  the service url we are checking.  probably best to leave it blank
 *   - `cas_host` the CAS host.  will fallback to environment variable CAS_HOST
 *
 * @param {Object} options
 * @return {Function}
 * @api public
 */


// set up logging per: https://gist.github.com/spmason/1670196
var logger = new winston.Logger()
var production = (env.NODE_ENV || '').toLowerCase() === 'production';
// express/connect also defaults to looking at env.NODE_ENV

// Override the built-in console methods with winston hooks
var loglevel = env.CAS_VALIDATE_LOGLEVEL || env.LOGLEVEL

switch(((env.NODE_ENV) || '').toLowerCase()){
    case 'production':
        production = true
        loglevel='warn'
        logger.add(winston.transports.File,
            {filename: __dirname + '/application.log'
                ,handleExceptions: true
                ,exitOnError: false
                ,level: 'warn'
                ,label: 'cas_validate'
            });
        break
    case 'test':
        // Don't set up the logger overrides
        break
    case 'development':
        loglevel='debug'
        logger.add(winston.transports.Console,
            {colorize: true
                ,timestamp: true
                ,level: loglevel
                ,label: 'cas_validate'
            });
        break
    default:
        loglevel = 'info'
        logger.add(winston.transports.Console,
            {colorize: true
                ,timestamp: true
                ,level: loglevel
                ,label: 'cas_validate'
            });
        break
    // make loglevels consistent
}
logger.setLevels(winston.config.syslog.levels);



function username(req,res,next){
    res.setHeader('Content-Type','application/json');
    if(req.session !== undefined && req.session.name !== undefined){
        return res.end(JSON.stringify({'user':req.session.name}));
    }else{
        return res.end(JSON.stringify({'user':null}));
    }
}

// these should be settable options
var validation_service = '/cas/serviceValidate';
var login_service = '/cas/login';
var json_validation_service = '/cas/jsonValidate';



function session_or_abort(){
    return function(req,res,next){
        if(req.session !== undefined  && req.session.st){
            logger.debug('have session.  steady as she goes');
            // okay, pass control
            return next();
        }else{
            logger.debug('no session, switch to next route');
            return next('route');//new Error('unauthorized'));
        }
    }
}

function check_or_redirect(options){
    // if no session, and no ticket in request, then redirect;
    // service param is optional, will default to whatever URL is used in the request

    var cas_host = options.cas_host
    if (! cas_host ) throw new Error('no CAS host specified');



    var gateway = options.gateway; // default to false

    return function(req,res,next){
        var url = parseUrl(req.url,true);

        logger.info('check_or_redirect: Url requested ' + req.originalUrl);

        var service = options.service + req.originalUrl; // for example: 'http://safety.ctmlabs.net/geojson';

        if(req.session !== undefined  && req.session.st){

            // okay, pass control
            logger.info('check_or_redirect: have session and session.st')

            return next();
        }

        // still here? redirect to CAS server
        var queryopts = {'service':service};
        if(gateway){
            queryopts.gateway = gateway;
        }
        logger.info('check_or_redirect: no current session, redirecting to CAS server') ;
        // previous version had an if here, with a 403 if request was
        // a json, but that never worked anyway

        res.writeHead(307, { 'location': cas_host+login_service
            +'?'
            +querystring.stringify(queryopts)
        });
        return res.end();
    }
}

function check_no_redirect(options){
    _.extend(options, {'gateway':true});
    return redirect(options);
}

function redirect(options){
    // if no session, and no ticket in request, then redirect;
    // service param is optional, will default to whatever URL is used in the request

    var cas_host = options.cas_host;
    if (! cas_host ) throw new Error('no CAS host specified');

    var gateway = options.gateway; // default to false
    var service = options.service;

    return function(req,res,next){
        //  redirect to CAS server

        var queryopts = {'service':service};
        if(gateway){
            // prevent an infinite loop
            if(req.session.gateway !== undefined){
                logger.debug('gateway already checked')
                return next()
            }
            logger.debug('gateway check to be done')
            req.session.gateway = true
            queryopts.gateway = gateway;
        }
        // previous version had an if here, with a 403 if request was
        // a json, but that never worked anyway
        res.writeHead(307, { 'location': cas_host+login_service
            +'?'
            +querystring.stringify(queryopts)
        });
        return res.end();
    }
}



function logout(options){
    var cas_host = options.cas_host;
    if (! cas_host ) throw new Error('no CAS host specified');
    var service = options.service;

    return function(req,res,next){
        // for logging out directly
        // I'd use async.parallel here, but no real need
        var logouturl = cas_host + '/cas/logout';


        req.session.destroy(function(err){
            if(err){
                logger.error(err)
            }
        });
        res.writeHead(307, { 'location': logouturl });
        res.end()
    }
}




function json_ticket(options)
{
    var json_uri = json_validation_service;

    if('json_service' in options)
    {
        json_uri = options.json_service;
    }

    var cas_host = options.cas_host;
    if (! cas_host ) throw new Error('no CAS host specified');
    var service = options.service;

    return function (req, res, next)
    {
        var url = parseUrl(req.url, true);

        if(url.query === undefined || url.query.ticket === undefined){
            logger.info('json_ticket: moving along, no ticket');
            return next();
        }
        logger.info('json_ticket: have ticket');

        if(req.session.st !== undefined
            && req.session.st == url.query.ticket){
            logger.info('json_ticket: ticket already checked');
            return next()
        }
        logger.info('json_ticket: checking ticket');
        req.session.st = url.query.ticket;
        logger.info('json_ticket: Checking ticket ' + req.session.st);

        // strip the search string off the service url
        var service = options.service + req.originalUrl.replace(url.search,'');
        logger.info('json_ticket: Validating service ' + service);


        // validate the service ticket
        var ticket = url.query.ticket;

        var cas_uri =  cas_host+json_uri
            +'?'
            +querystring.stringify(
            {'service':service,
                'ticket': ticket});

        logger.debug('json_ticket: firing: '+cas_uri);
        request({uri:cas_uri}, function (error, response, body) {
            logger.info(body);

            if (!error && response.statusCode == 200) {


                if(/cas:authenticationFailure/.exec(body))
                {
                    logger.error('json_ticket: Authentication failed or invalid ticke!' + body);
                    next(new Error('json_ticket: Authentication failed or invalid ticket'));
                } else {

                    var result = JSON.parse(body);
                    req.session.st = ticket;
                    req.session.user = result;
                    next();
                }
            }else{
                logger.debug('json_ticket: auth failed') ;
                logger.error(error);
                // okay, not logged in, but don't get worked up about it
                next(new Error('json_ticket: authentication failed'));
            }
            return null;

        });
        return null;
    }

}


exports.redirect = redirect;
exports.check_or_redirect = check_or_redirect;
exports.check_and_return = check_no_redirect;
exports.json_ticket = json_ticket;
exports.logout = logout;
exports.username = username;
exports.session_or_abort = session_or_abort;
