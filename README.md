## Password Hash

**Password Hash** is the implementation from Membership Reboot 

### Hashing Algorithm

It uses the [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) function to generate a password using the algorithm [Rfc2898derivebytes]((http://msdn.microsoft.com/en-us/library/system.security.cryptography.rfc2898derivebytes(v=vs.110).aspx)) from the base class library.

### PBKDF2

> PBKDF2 applies a pseudorandom function, such as a cryptographic hash, cipher, or HMAC to the input password or passphrase along with a salt value and repeats the process many times to produce a derived key, which can then be used as a cryptographic key.

This just means that over time [Moore's law](http://en.wikipedia.org/wiki/Moore's_law) makes it easier for hashes to be brute forced. So the function used to generate passwords need to become more expensive over time.

The membership reboot allows you to set an iteration count or allow it to uses a default based on years.  The resultant hash is a single string.  {IterationCount as Hex}.{Base64 (Hash + Salt)}. 

### Rfc2898derivebytes


Is the hash algorithm used to generates the actual hash from the password cleartext.

### Framework implementation

The System.Web.Helper uses the same set up to hash password but unlike the membership reboot does not allow you to set an iteration count or provide an increasing default it just uses a constant count of 1000.   

### Code example

    var sut = new DefaultCrypto();

    var password = "password";
	//uses iteration based on currnt year
    var hash = sut.HashPassword(password);

    var isValid = sut.VerifyHashedPassword(hash, password);

	//or set the iteration
	var hash = sut.HashPassword(password, 10000);

    var isValid = sut.VerifyHashedPassword(hash, password);