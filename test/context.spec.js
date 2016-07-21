import { expect } from 'chai';
import Context from '../src/context.js';
import ip from 'ip';
import 'babel-polyfill';

describe('context', () => {
  let context;
  const INVALID_RESOURCES = [undefined, null];
  const INVALID_RESOURCES_TYPES = [Object, Number, Boolean, Array, Date, Function];
  const INVALID_CIDR = ['', undefined, null, '127.0.1/32', '0.0.0.0', 'subnet'];

  function *allInRange(cidr) {
    const subnet = ip.cidrSubnet(cidr);
    for (let addr = ip.toLong(subnet.firstAddress); addr < ip.toLong(subnet.lastAddress); addr++) {
      yield ip.fromLong(addr);
    }
  }

  beforeEach(() => {
    context = new Context();
  });

  it('should be able to create a context object', () => {
    expect(context).to.be.ok;
  });

  it('should be able to add rules for a single resource', () => {
    context.forResource('/resource/path');
  });

  it('should be able to add rules for subset of resources', () => {
    context.forResource('/resource/path/*');
  });

  it('should accept a string object as resource', () => {
    // eslint-disable-next-line no-new-wrappers
    expect(() => context.forResource(new String('/resource/path'))).not.to.throw();
  });

  INVALID_RESOURCES.forEach((invalidResource) => {
    it(`should fail to add invalid resource: ${invalidResource}`, () => {
      expect(() => context.forResource(invalidResource)).to.throw(Error);
    });
  });

  INVALID_RESOURCES_TYPES.forEach((invalidType) => {
    it(`should fail to add resource of type ${invalidType.name}`, () => {
      const typeInstance = Object.create(invalidType);
      expect(() => context.forResource(typeInstance)).to.throw(Error);
    });
  });

  it('should be able to add multiple resources at once', () => {
    expect(() => {
      context.forResource('/protected/resource/1')
             .forResource('/protected/resource/2')
             .forResource('/protected/resource/3')
             .forResource('/protected/resource/4/*');
    }).not.to.throw();
  });

  it('should fail to add duplicate resources', () => {
    expect(() => {
      context.forResource('/resource')
             .forResource('/resource');
    }).to.throw(Error);
  });

  it('should fail to add duplicate subset of resources', () => {
    expect(() => {
      context.forResource('/resource/*')
             .forResource('/resource/*');
    }).to.throw(Error);
  });

  it('should be able to add more specific rules for same resource', () => {
    expect(() => {
      context.forResource('/protected/resource/1')
             .forResource('/protected/resource/2')
             .deny('*')
             .forResource('/protected/resource/1')
             .allow('127.0.0.1/32')
             .forResource('/protected/resource/2')
             .allow('192.168.0.0/24');
    }).not.to.throw(Error);
  });

  INVALID_CIDR.forEach((cidr) => {
    it(`should only accept valid CIDR or '*': ${cidr}`, () => {
      expect(() => {
        context.forResource('/path')
               .allow(cidr);
      }).to.throw(Error);
    });
  });

  it('should be able to add rules from config', () => {
    expect(() => new Context([
      {
        resource: '*',
        allow: '127.0.0.1/32',
        deny: '*'
      },
      {
        resource: '/protected/resource/1',
        allow: '*'
      },
      {
        resource: ['/protected/resource/2', '/protected/resource/3'],
        allow: '192.168.0.0/24'
      },
      {
        resource: '/protected/resource/4',
        allow: ['192.168.0.0/24', '192.168.1.0/24']
      }
    ])).not.to.throw(Error);
  });

  it('should fail if config is malformed', () => {
    expect(() => new Context({})).to.throw(Error);
    expect(() => new Context([{}])).to.throw(Error);
    expect(() => new Context([{ allow: '*' }])).to.throw(Error);
    expect(() => new Context([{ resource: '*' }])).to.throw(Error);
  });

  it('should deny access to some resource', () => {
    const isAllowed = context.forResource('/path').deny('*').build();
    const allowed = isAllowed('/path', ip.address());
    expect(allowed).to.be.false;
  });

  it('should deny access subset of resources', () => {
    const isAllowed = context.forResource('/path/*').deny('*').build();
    expect(isAllowed('/path/1', ip.address())).to.be.false;
    expect(isAllowed('/path/1/2', ip.address())).to.be.false;
  });

  it('should allow access to some resource for all addresses of given ranges', () => {
    const allowedRanges = ['192.168.0.1/24', '172.10.154.100/25', '127.0.0.1/32'];
    context.forResource('/path').deny('*');
    allowedRanges.forEach((range) => {
      context.allow(range);
    });

    const isAllowed = context.build();

    allowedRanges.forEach((range) => {
      for (const addr of allInRange(range)) {
        expect(isAllowed('/path', addr)).to.be.true;
      }
    });
  });

  it('should allow access to subset of resources for all addresses of given ranges', () => {
    const allowedRanges = ['192.168.0.1/24', '172.10.154.100/25', '127.0.0.1/32'];
    context.forResource('/path/*').deny('*');
    allowedRanges.forEach((range) => {
      context.allow(range);
    });

    const isAllowed = context.build();

    allowedRanges.forEach((range) => {
      for (const addr of allInRange(range)) {
        expect(isAllowed('/path/1', addr)).to.be.true;
        expect(isAllowed('/path/1/2', addr)).to.be.true;
      }
    });
  });

  it('should deny access to some resource for all addresses of given ranges', () => {
    const allowedRanges = ['192.168.0.1/24', '172.10.154.100/25', '127.0.0.1/32'];
    context.forResource('/path').allow('*');
    allowedRanges.forEach((range) => {
      context.deny(range);
    });

    const isAllowed = context.build();

    allowedRanges.forEach((range) => {
      for (const addr of allInRange(range)) {
        expect(isAllowed('/path', addr)).to.be.false;
      }
    });
  });

  it('should deny access to subset of resources for all addresses of given ranges', () => {
    const allowedRanges = ['192.168.0.1/24', '172.10.154.100/25', '127.0.0.1/32'];
    context.forResource('/path/*').allow('*');
    allowedRanges.forEach((range) => {
      context.deny(range);
    });

    const isAllowed = context.build();

    allowedRanges.forEach((range) => {
      for (const addr of allInRange(range)) {
        expect(isAllowed('/path/1', addr)).to.be.false;
        expect(isAllowed('/path/1/2', addr)).to.be.false;
      }
    });
  });

  it('should allow access to some resource for multiple nested ranges', () => {
    const isAllowed = context
      .forResource('/path')
      .deny('*')
      .allow('192.168.0.1/24') // 192.168.0.1 to 192.168.0.255
      .deny('192.168.0.1/25')  // 192.168.0.1 to 192.168.0.127
      .build();
    expect(isAllowed('/path', '104.16.39.59')).to.be.false;
    expect(isAllowed('/path', '192.168.0.1')).to.be.false;
    expect(isAllowed('/path', '192.168.0.127')).to.be.false;
    expect(isAllowed('/path', '192.168.0.128')).to.be.true;
    expect(isAllowed('/path', '192.168.0.254')).to.be.true;
  });

  it('should allow access to subset of resources for multiple nested ranges', () => {
    const isAllowed = context
      .forResource('/path/*')
      .deny('*')
      .allow('192.168.0.1/24') // 192.168.0.1 to 192.168.0.255
      .deny('192.168.0.1/25')  // 192.168.0.1 to 192.168.0.127
      .build();
    expect(isAllowed('/path/1', '104.16.39.59')).to.be.false;
    expect(isAllowed('/path/1/2', '104.16.39.59')).to.be.false;
    expect(isAllowed('/path/1', '192.168.0.1')).to.be.false;
    expect(isAllowed('/path/1/2', '192.168.0.1')).to.be.false;
    expect(isAllowed('/path/1', '192.168.0.127')).to.be.false;
    expect(isAllowed('/path/1/2', '192.168.0.127')).to.be.false;
    expect(isAllowed('/path/1', '192.168.0.128')).to.be.true;
    expect(isAllowed('/path/1/2', '192.168.0.128')).to.be.true;
    expect(isAllowed('/path/1', '192.168.0.254')).to.be.true;
    expect(isAllowed('/path/1/2', '192.168.0.254')).to.be.true;
  });
});
