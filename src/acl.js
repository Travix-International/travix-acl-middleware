import Context from './context';
import { FORBIDDEN, X_FORWARDED_FOR_HEADER } from './constants';

/**
 * Produces an ACL middleware component.
 *
 * @param  {Object}          [options]                 options object
 * @param  {Function}        [options.configure]       a function that accepts a context and uses it to configure the rules
 * @param  {Number|Function} [options.respondWith]     either a function that returns an http status code or a number literal representing the status code; default: 403
 * @param  {handleResponse}  [options.handleResponse]  a function to handle an forbidden request
 * @return {Function}   ACL middleware
 */
export default function acl(options) {
  const {
    configure = function configure() { },
    respondWith = FORBIDDEN,
    handleResponse = function handleResponse(res, statusCode) {
      res.status(statusCode);
      res.end();
    }
  } = options;

  const ctx = new Context();
  configure(ctx);
  const isAllowed = ctx.build();

  /**
   * ACL middleware.
   * @param {Object}   req   express request object
   * @param {Object}   res   express response object
   * @param {Function} next  invokes next middleware in chain
   */
  const ACLMiddleware = function aclMiddleware(req, res, next) {
    const remoteAddr = req.headers[X_FORWARDED_FOR_HEADER] || req.connection.remoteAddress;
    if (isAllowed(req.path, remoteAddr)) {
      next();
      return;
    }
    const statusCode = (typeof respondWith === 'function') ? respondWith(req) : respondWith;
    handleResponse(res, statusCode);
    return;
  };

  return ACLMiddleware;
}
