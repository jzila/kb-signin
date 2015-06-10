## Synopsis

This library cooperates with [this chrome extension](https://github.com/jzila/kb-login-ext),
allowing implementing websites to support signin by validating a signature against Keybase's
public key repository.

The library supports authenticating against a Keybase username, email address, or key fingerprint.

## Development

This library can interact with AWS lambda or [Express](http://expressjs.com/)
response objects.

[Here](https://github.com/jzila/static-aws-blog/tree/master/lambda) is a demo
showing how you can create lambda functions to authenticate even a [static
website](https://github.com/jzila/static-aws-blog/tree/master/static) using AWS
Lambda and Cognito.

[Here](https://github.com/jzila/kb-login-ext/blob/master/demo-server/server.js)
is a demo showing how you can authenticate an express app.


## Contributing

Feel free to submit pull requests or issues.

## License

The MIT License (MIT)

Copyright (c) 2015 John Zila

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

#### [Node.JS License](https://raw.githubusercontent.com/joyent/node/v0.10.36/LICENSE)

#### [Kbpgp License](https://raw.githubusercontent.com/keybase/kbpgp/master/LICENSE)

#### [Triplesec License](https://raw.githubusercontent.com/keybase/triplesec/master/LICENSE)

#### [JQuery License](https://jquery.org/license/)
