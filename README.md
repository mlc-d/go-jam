# Jam

JWT Authentication Middleware. This project is just an extension of the [`go-chi`](https://github.com/go-chi/jwtauth) middleware; it has a shameful amount of copy-paste, but it also includes some extra options to parse the token from (the original project has header and cookie lookup by default). Additionally, it borrows a lot of concepts / unambiguously steals ideas from the [`lestrrat-go/echo-middleware-jwx`](https://github.com/lestrrat-go/echo-middleware-jwx) project.

lestrrat is also the creator of the wonderful [`JWX`](https://github.com/lestrrat-go/jwx) package, one of the best and most complete implementations of the JWT Standards available in Go.

All the credit goes to the go-chi team and to lestrrat; my work was secondary, and it wouldn't have been possible without all the effort and contributions from them.

### Contributing
I encourage anyone to contribute with the original projects; nonetheless, if you feel like adding stuff to this repo, don't mind to check the [CONTRIBUTING](CONTRIBUTING.md) file.

### Licensing
[LICENSE](./LICENSE).
