# PHP-URL-Signer
Create URLs that are reasonably tamper resistant and have a limited life time.

```php
include( 'class-url-signer.php' );

$signer::sign( 'https://somedomainname.nul', '5 HOURS' );

// => The generated url will be valid for 5 hours
// => Use standard PHP strtotime() notation: '5 HOURS', '30 DAYS', '10 MINUTES', etc
// => Note: This works with URLs that have query parameters too. 
```
This will output a URL that looks like `https://somedomainname.nul/?expires=xxxx&signature=xxxx`.

Verify the URL like this: 

```php
include( 'class-url-signer.php' );

$result = $signer::verify( 'https://somedomainname.nul/?expires=xxxx&signature=xxxx' );

// => $result will be true or false
```

## Installation

Dirt simple installation: Copy the class file in your project. That's it, the class is self-contained and does not rely on any external code. 

It's been tested with PHP 7.2.x

## Hash algorithm

The code, as is, uses SHA256 since that is available in most PHP installations. You can change it to whatever your system supports if you have the need. 

## License
You're free to use this code however you see fit, it's licensed under GPLv2. Use at your own risk! No warranty is expressed nor implied.

The GPLv2 License:

https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
