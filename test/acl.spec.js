import chai, { expect } from 'chai';
import acl from '../src/acl';
import { sandbox } from 'sinon';
import { createRequest, createResponse } from 'node-mocks-http';

describe('acl', () => {
  const PATH = '/health_check';
  const ADDR = '::1';

  let middleware;
  let context;
  let req;
  let res;
  let next;
  let evaluateMock;

  function createMiddleware(otherOptions = {}) {
    const options = {
      configure(ctx) {
        context = ctx;
        sandbox.stub(context, 'build').returns(evaluateMock);
      }
    };
    Object.assign(options, otherOptions);
    middleware = acl(options);
  }

  chai.use(require('sinon-chai'));
  require('mocha-sinon');

  beforeEach(() => {
    sandbox.create();
    evaluateMock = sandbox.mock();
    createMiddleware();
    req = createRequest();
    res = createResponse();
    next = sandbox.spy();
    req.connection = { remoteAddress: ADDR };
    req.path = PATH;
    sandbox.spy(res, 'status');
  });

  afterEach(() => {
    sandbox.restore();
  });

  it('should call `context.build()` to obtain evaluate function', () => {
    middleware(req, res, next);
    expect(context.build).to.have.been.calledOnce;
  });

  it('should return 403 status code when evaluate returns false', () => {
    evaluateMock.returns(false);
    middleware(req, res, next);
    expect(evaluateMock).to.have.been.calledWith(PATH, ADDR);
    expect(res.status).to.have.been.calledWith(403);
    expect(next).not.to.have.been.called;
  });

  it('should call next when evaluate returns true', () => {
    evaluateMock.returns(true);
    middleware(req, res, next);
    expect(evaluateMock).to.have.been.calledWith(PATH, ADDR);
    expect(res.status).not.to.have.been.called;
    expect(next).to.have.been.calledOnce;
  });

  it('should be able to respond with a different than default status code', () => {
    evaluateMock.returns(false);
    createMiddleware({ respondWith: 404 });
    middleware(req, res, next);
    expect(evaluateMock).to.have.been.calledWith(PATH, ADDR);
    expect(res.status).to.have.been.calledWith(404);
    expect(next).not.to.have.been.called;
  });

  it('should be able to use a custom function to determine status code', () => {
    evaluateMock.returns(false);
    createMiddleware({
      respondWith() {
        return 500;
      }
    });
    middleware(req, res, next);
    expect(evaluateMock).to.have.been.calledWith(PATH, ADDR);
    expect(res.status).to.have.been.calledWith(500);
    expect(next).not.to.have.been.called;
  });

  it('should be able to handle response using custom function', () => {
    evaluateMock.returns(false);
    const handleResponse = sandbox.spy();
    createMiddleware({
      handleResponse
    });
    middleware(req, res, next);
    expect(evaluateMock).to.have.been.calledWith(PATH, ADDR);
    expect(handleResponse).to.have.been.calledOnce;
    expect(next).not.to.have.been.called;
  });
});
