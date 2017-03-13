# mbed-client-mbedtls
Uses PAL TLS to provide TLS support for [mbed client](https://github.com/ARMmbed/mbed-client). The module that directly uses this API is [mbed-client-classic](https://github.com/ARMmbed/mbed-client-classic).

## Running unit tests
1. Use the following command to clone required git repositories:

        make clone

2. After the cloning is done run the unit tests with:

        make test
    
### Pre-requisites for the unit tests
install the following tools:
- CppUTest
- XSL
- lcov
- gcovr
- Ninja 

To install these tools on Ubuntu run the following commands:

    sudo apt-get install cpputest
    sudo apt-get install xsltproc
    sudo apt-get install lcov
    sudo apt-get install gcovr
    sudo apt-get install ninja-build
