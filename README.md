# travix-acl-middleware

Express middleware for ACL to be used in all Express servers used by Travix.


### Usage & Examples

#### Configuring the ACL middleware

```
import express from 'express';
import acl from 'acl';

const app = express();
app.use(acl({
  // optional configuration function
  configure(context) {
    // allow health check endpoint to be accessible only from localhost
    context.forResource('/health_check')
           .deny('*')
           .allow('127.0.0.1/32');

    // allow protected resources to be accessible only from the internal network (192.168.0.*)
    // and let '/protected/resource/1' to be accessible by a few external ips
    context.forResource('/protected/resource/1')
           .forResource('/protected/resource/2')
           .deny('*')
           .allow('192.168.0.1/24')
           .forResource('/protected/resource/1')
           .allow('104.16.35.24/29');


    // blacklisting bad ip from accessing home page
    var BAD_IP = '123.456.789.001/32';
    context.forResource('/')
           .allow('*')
           .deny(BAD_IP);
  },
  // optional preconfigured rules
  predefinedRules: [
    {
      resource: '/protected/resource/3',
      allow: '192.168.0.1/24',
      deny: '*'
    },
    {
      resource: ['/protected/resource/4', '/protected/resource/5'],
      allow: '*',
      deny: ['192.168.0.1/24', '192.168.1.1/24']
    }
  ]
}));

```

> Note: express-style path strings are also supported, see [path-to-regexp](https://www.npmjs.com/search?q=path-to-regexp) repository for more info.

#### Redefine Http Status code returned

By default, any blocked requests will return status code `403 FORBIDDEN`. You can redefine it using the `options.respondWith` property.  For instance:

```
app.use(acl({
  configure() {
    ...
  },
  predefinedRules: [...],
  respondWith: 404
}));

```

This will respond with a `404 NOT FOUND` status instead.

```
app.use(acl({
  configure() {
    ...
  },
  predefinedRules: [...],
  respondWith(req) {
    if (req.path === '/health_check') {
      return 404;
    }
    return 400;
  }
}))
```

This will respond with a `404 NOT FOUND` status for the health check endpoint, but return `400 BAD REQUEST` for all other blocked requests.

#### Custom Response

If you prefer, you can handle the response yourself by providing a `handleResponse` function:

```
app.use(acl({
  configure() {
    ...
  },
  predefinedRules: [...],
  handleResponse(res, statusCode) {
     res.status(statusCode)
        .send("We're sorry, you don't have access to the page you requested. Please go back to the homepage");
  }
}));
```
