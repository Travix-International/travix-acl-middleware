import { ALLOW, DENY, CATCH_ALL, CATCH_ALL_CIDR } from './constants';
import { isArray, isEmpty, isString, memoize } from 'lodash';
import ip from 'ip';
import pathToRegexp from 'path-to-regexp';

/* A rule objec that allows access to all addresses */
const ACCEPT_ALL_RULE = { allow: true, subnet: ip.cidrSubnet(CATCH_ALL_CIDR) };

/**
 * A context object that is used to configure the access rules.
 */
export default class Context {

  /**
   * Constructor
   */
  constructor(config = {}) {
    this.patterns = [];
    this.rules = {};
    this.lastAddedResources = [];

    let { allow = [], deny = [] } = config;
    if (allow === CATCH_ALL) {
      allow = [[CATCH_ALL, CATCH_ALL]];
    } else if (!isArray(allow)) {
      throw new Error('Allow section has to be an array');
    }
    if (deny === CATCH_ALL) {
      deny = [[CATCH_ALL, CATCH_ALL]];
    } else if (!isArray(deny)) {
      throw new Error('Deny section has to be an array');
    }

    const add = (ruleType, pairs) => {
      for (const pair of pairs) {
        if (!isArray(pair)) {
          throw new Error('Rule has to be an array');
        }
        const [paths, cidrs] = pair;
        for (const path of isArray(paths) ? paths : [paths]) {
          this.forResource(path);
        }
        for (const cidr of isArray(cidrs) ? cidrs : [cidrs]) {
          this.addRule(ruleType, cidr);
        }
      }
    }

    add(ALLOW, allow);
    add(DENY, deny);
  }

  /**
   * Registers a resource path to be added rules
   * @param  {String}  path  resource path
   * @return {Object}  a self reference
   * @chainable
   */
  forResource(path) {
    path = this.validatePath(path);
    if (this.lastAddedResources.some((resource) => !isEmpty(this.rules[resource]))) {
      this.lastAddedResources = [];
    }
    const pattern = pathToRegexp(path);
    pattern.length = path.length;
    const resource = (pattern.keys.length ? pattern : path).toString();
    if (pattern.keys.length) {
      this.patterns.push(pattern);
    }
    this.validateDuplicateResource(resource);
    this.lastAddedResources.push(resource);
    this.rules[resource] = this.rules[resource] || [];
    return this;
  }

  /**
   * Add a rule of type 'allow'
   * @param  {String}  cidr  a string representing a classless inter-domain routing block
   * @return {Object}  a self reference
   * @chainable
   */
  allow(cidr) {
    this.addRule(ALLOW, cidr);
    return this;
  }

  /**
   * Add a rule of type 'deny'
   * @param  {String}  cidr  a string representing a classless inter-domain routing block
   * @return {Object}  a self reference
   * @chainable
   */
  deny(cidr) {
    this.addRule(DENY, cidr);
    return this;
  }

  /**
   * Add rule
   * @param  {String} ruleType  either 'allow' or 'deny'
   * @param  {String} cidr      cidr
   * @private
   */
  addRule(ruleType, cidr) {
    cidr = this.validateCidr(cidr);
    this.lastAddedResources.forEach((resource) => {
      this.rules[resource].push({ type: ruleType, cidr, children: [] });
    });
  }

  /**
   * Generates a function based on the specified rules
   * @return {Function}  function used to evaluate rules
   */
  build() {
    this.patterns.sort(pattern => pattern.length);
    return memoize(this.isAllowed.bind(this), (...args) => args.splice(0, 2).join(' '));
  }

  /**
   * Determines if given remote address has access to resource
   * @param  {String}  resource  resource name
   * @param  {String}  addr      remote address
   * @return {Boolean} returns 'true' if remote address has access to resource; otherwise 'false'
   * @private
   */
  isAllowed(resource, addr) {
    const resourceRules = this.getResourceRules(resource);
    const applicableRules = resourceRules.filter(this.applicable(addr));
    const mostSpecificRule = this.getMostSpecificRule(applicableRules);
    return mostSpecificRule.allow;
  }

  /**
   * Gets all rules for given resource
   * @param  {String} resource  resource name
   * @return {Array}  a list of rules
   * @private
   */
  getResourceRules(resource) {
    return this.patterns
      .filter((pattern) => pattern.test(resource))
      .concat(resource)
      .reduce(
        (rules, key) => {
          if (key in this.rules) {
            return rules.concat(this.rules[key].map((rule) => ({
              subnet: ip.cidrSubnet(rule.cidr),
              allow: rule.type === ALLOW
            })));
          }
          return rules;
        },
        []);
  }

  /**
   * Produces a function that is used to determine if given rule is applicable to remote address
   * @param  {String}  addr  remote address
   * @return {Function}  determines if rule applies to remote address
   * @private
   */
  applicable(addr) {
    return (rule) => rule.subnet.contains(addr);
  }

  /**
   * Gets the most specific rule for the given remote address
   * @param  {Array}   rules  a collection of rules
   * @return {Object}  most specific rule applicable to remote address
   * @private
   */
  getMostSpecificRule(rules) {
    return rules.reduce((prev, current) => {
      if (prev.subnet.length === current.subnet.length) {
        return { subnet: current.subnet, allow: current.allow && prev.allow };
      }
      return prev.subnet.length < current.subnet.length ? prev : current;
    }, ACCEPT_ALL_RULE);
  }

  /**
   * Validates if resource path is valid.
   * @param  {String}  path  resource path
   * @throws {Error}   throw error if resource path is invalid
   */
  validatePath(path) {
    if (!isString(path)) {
      throw new Error('Path has to be a valid string value');
    }
    return path;
  }

  /**
   * Validate if resource is duplicate
   * @param  {String}  path  resource path
   * @throws {Error}   throws error if resource is duplicate
   */
  validateDuplicateResource(path) {
    if (this.lastAddedResources.includes(path)) {
      throw new Error('Duplicate resource name');
    }
  }

  /**
   * Validate if CIDR is valid; Convert '*' (catch all) to catch all CIDR
   * @param  {String}  cidr class-less inter-domain routing block
   * @throws {Error}   throw error if CIDR is invalid
   * @return {String}  string representing the CIDR
   */
  validateCidr(cidr) {
    if (cidr === CATCH_ALL) {
      cidr = CATCH_ALL_CIDR;
    }
    this.ensureIsValidCidr(cidr);
    return cidr;
  }

  /**
   * Ensures that CIDR is valid
   * @param  {String}  cidr  classless inter-domain routing block
   * @throws {Error}   throws error if CIDR is not valid
   * @return {Object}  an object representing the CIDR
   */
  ensureIsValidCidr(cidr) {
    return ip.cidr(cidr);
  }
}
